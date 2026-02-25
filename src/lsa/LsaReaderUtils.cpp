#include "lsa/LsaReaderUtils.h"

#include "lsa/LsaStructures.h"

#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace KvcForensic::lsa {

std::string ComputeSha1(std::span<const std::byte> data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::string result;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (status != 0) return result;

    DWORD obj_size = 0, dummy = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&obj_size), sizeof(obj_size), &dummy, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return result; }

    std::vector<BYTE> hash_object(obj_size);
    std::vector<BYTE> hash_result(20);

    status = BCryptCreateHash(hAlg, &hHash, hash_object.data(), obj_size, NULL, 0, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return result; }

    status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())),
                            static_cast<ULONG>(data.size()), 0);
    if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return result; }

    status = BCryptFinishHash(hHash, hash_result.data(), static_cast<ULONG>(hash_result.size()), 0);
    if (status == 0) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (const auto b : hash_result)
            ss << std::setw(2) << static_cast<int>(b);
        result = ss.str();
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

std::wstring Utf16ToWString(const std::vector<std::byte>& data) {
    std::wstring str;
    str.reserve(data.size() / 2);
    for (std::size_t i = 0; i + 1 < data.size(); i += 2) {
        std::uint16_t ch = static_cast<std::uint8_t>(data[i]) | (static_cast<std::uint8_t>(data[i + 1]) << 8);
        str.push_back(static_cast<wchar_t>(ch));
    }
    return str;
}

std::wstring BytesToHexString(std::span<const std::byte> bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (const auto b : bytes)
        ss << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(b));
    return ss.str();
}

bool IsLikelyReadablePassword(const std::wstring& text) {
    if (text.empty()) return false;
    if (text.size() > 512) return false;

    std::size_t printable = 0;
    for (const auto ch : text) {
        if (ch == L'\0') return false;
        if (ch == L'\r' || ch == L'\n' || ch == L'\t') { printable++; continue; }
        if (iswprint(ch) != 0) printable++;
    }
    return printable * 100 >= text.size() * 85;
}

void DecodePasswordCandidate(
    const std::vector<std::byte>& decrypted,
    const std::uint16_t utf16_byte_len_hint,
    std::wstring& out_password,
    std::wstring& out_password_hex) {

    out_password.clear();
    out_password_hex.clear();
    if (decrypted.empty()) return;

    std::size_t take = decrypted.size();
    if (utf16_byte_len_hint > 0)
        take = (std::min)(take, static_cast<std::size_t>(utf16_byte_len_hint));
    if ((take & 1u) != 0u) --take;
    if (take == 0) return;

    const std::size_t hex_cap = (std::min)(take, static_cast<std::size_t>(4096));
    out_password_hex = BytesToHexString(std::span<const std::byte>(decrypted.data(), hex_cap));
    if (hex_cap < take) out_password_hex += L"...";

    std::vector<std::byte> candidate(decrypted.begin(), decrypted.begin() + take);
    std::wstring decoded = Utf16ToWString(candidate);
    while (!decoded.empty() && decoded.back() == L'\0') decoded.pop_back();
    if (IsLikelyReadablePassword(decoded)) out_password = decoded;
}

// ---------------------------------------------------------------------------

std::wstring ReadUnicodeString(const core::VirtualMemory& vmem, const std::uint64_t string_va) {
    UNICODE_STRING64 ustr{};
    if (!vmem.ReadStruct(string_va, &ustr)) return L"";
    if (ustr.Length == 0 || ustr.Buffer == 0) return L"";
    const std::uint16_t safe_len = (std::min)(ustr.Length, static_cast<std::uint16_t>(1024));
    std::vector<std::byte> buffer(safe_len);
    if (!vmem.ReadBytes(ustr.Buffer, safe_len, buffer)) return L"";
    return Utf16ToWString(buffer);
}

std::string ReadSid(const core::VirtualMemory& vmem, const std::uint64_t sid_va) {
    if (sid_va == 0) return "None";

    std::uint8_t revision = 0;
    if (!vmem.ReadStruct(sid_va, &revision)) return "None";

    std::uint8_t sub_authority_count = 0;
    if (!vmem.ReadStruct(sid_va + 1, &sub_authority_count)) return "None";
    if (sub_authority_count > 15) sub_authority_count = 15;

    std::vector<std::uint8_t> identifier_authority(6);
    if (!vmem.ReadBytes(sid_va + 2, 6,
            std::span<std::byte>(reinterpret_cast<std::byte*>(identifier_authority.data()), 6)))
        return "None";

    std::uint64_t auth = 0;
    for (int i = 0; i < 6; ++i) auth = (auth << 8) | identifier_authority[i];

    std::ostringstream ss;
    ss << "S-" << static_cast<int>(revision) << "-" << auth;
    for (int i = 0; i < sub_authority_count; ++i) {
        std::uint32_t sub_auth = 0;
        if (!vmem.ReadStruct(sid_va + 8 + (i * 4), &sub_auth)) break;
        ss << "-" << sub_auth;
    }
    return ss.str();
}

std::uint64_t FindSignatureInModule(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    const std::wstring& module_name,
    const std::vector<std::uint8_t>& sig) {

    const minidump::ModuleInfo* mod = nullptr;
    for (const auto& m : metadata.modules) {
        std::wstring name_lower = m.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::towlower);
        std::wstring search_lower = module_name;
        std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(), ::towlower);
        if (name_lower.find(search_lower) != std::wstring::npos) { mod = &m; break; }
    }
    if (!mod) return 0;

    for (const auto& range : metadata.memory_ranges) {
        const std::uint64_t start = (std::max)(range.start_vva,
            static_cast<std::uint64_t>(mod->base_address));
        const std::uint64_t end = (std::min)(range.start_vva + range.size,
            static_cast<std::uint64_t>(mod->base_address + mod->size));
        if (start >= end || (end - start) < sig.size()) continue;

        std::vector<std::byte> chunk(end - start);
        if (!vmem.ReadBytes(start, chunk.size(), chunk)) continue;

        for (std::size_t i = 0; i <= chunk.size() - sig.size(); ++i) {
            if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0)
                return start + i;
        }
    }
    return 0;
}

} // namespace KvcForensic::lsa
