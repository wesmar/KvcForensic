#include "lsa/TspkgWalker.h"

#include "lsa/LsaReaderUtils.h"

#include <set>
#include <vector>

namespace KvcForensic::lsa {

TspkgWalker::TspkgWalker(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    security::LsaSecretsExtractor* extractor,
    const templates::TspkgTemplateSpec* tmpl)
    : vmem_(vmem), metadata_(metadata), extractor_(extractor), tmpl_(tmpl) {}

// ---------------------------------------------------------------------------
// Parse the decrypted TSPKG credentials blob.
//
// Layout after decryption (see TemplateRegistry.h / TspkgTemplateSpec):
//
//   [blob_header_skip bytes — e.g. DWORD MessageType + 4-byte pad if present]
//   UNICODE_STRING LogonDomainName  (Length 2 + MaxLength 2 + pad 4 + Buffer 8 = 16 B)
//   UNICODE_STRING UserName         (16 B)
//   UNICODE_STRING Password         (16 B)
//   <raw UTF-16 string bytes>       (domain || username || password, each Length bytes)
//
// Buffer VA values inside the UNICODE_STRING headers are process addresses and
// cannot be used as offsets here; instead we derive offsets from the Length
// fields relative to the header block end.
// ---------------------------------------------------------------------------
static void ParseTspkgBlob(
    const std::vector<std::byte>& decrypted,
    const std::size_t blob_header_skip,
    std::wstring& out_domain,
    std::wstring& out_username,
    std::wstring& out_password,
    std::wstring& out_password_hex)
{
    // Minimum blob: skip + 3 × 16-byte UNICODE_STRING headers = skip + 48.
    constexpr std::size_t kHeaderSize = 3 * 16;
    if (decrypted.size() < blob_header_skip + kHeaderSize) return;

    const std::byte* p = decrypted.data() + blob_header_skip;

    auto ReadUStr = [&](std::size_t off, std::uint16_t& len, std::uint16_t& maxlen) {
        std::memcpy(&len,    p + off,     2);
        std::memcpy(&maxlen, p + off + 2, 2);
    };

    std::uint16_t domain_len   = 0, domain_max   = 0;
    std::uint16_t user_len     = 0, user_max     = 0;
    std::uint16_t pwd_len      = 0, pwd_max      = 0;

    ReadUStr(0,  domain_len, domain_max);
    ReadUStr(16, user_len,   user_max);
    ReadUStr(32, pwd_len,    pwd_max);

    // Sanity check: lengths must be even (UTF-16), reasonable, and fit in blob.
    const std::size_t data_start = blob_header_skip + kHeaderSize;
    const std::size_t need = static_cast<std::size_t>(domain_max) +
                              static_cast<std::size_t>(user_max)   +
                              static_cast<std::size_t>(pwd_max);
    if ((domain_len & 1) || (user_len & 1) || (pwd_len & 1)) return;
    if (domain_len > 512 || user_len > 512 || pwd_len > 512) return;
    if (data_start + need > decrypted.size()) {
        // Fall back: try without blob_header_skip (maybe MessageType missing)
        if (blob_header_skip > 0) {
            ParseTspkgBlob(decrypted, 0, out_domain, out_username,
                           out_password, out_password_hex);
        }
        return;
    }

    auto ExtractUtf16 = [&](std::size_t offset, std::uint16_t byte_len) -> std::wstring {
        if (byte_len == 0 || offset + byte_len > decrypted.size()) return {};
        std::wstring s;
        s.reserve(byte_len / 2);
        for (std::size_t i = offset; i + 1 < offset + byte_len; i += 2) {
            std::uint16_t ch = static_cast<std::uint8_t>(decrypted[i]) |
                               (static_cast<std::uint8_t>(decrypted[i + 1]) << 8);
            s.push_back(static_cast<wchar_t>(ch));
        }
        while (!s.empty() && s.back() == L'\0') s.pop_back();
        return s;
    };

    std::size_t cur = data_start;
    out_domain   = ExtractUtf16(cur, domain_len); cur += domain_max;
    out_username = ExtractUtf16(cur, user_len);   cur += user_max;

    // Password: raw bytes + hex
    if (pwd_max > 0 && cur + pwd_max <= decrypted.size()) {
        const std::size_t take = static_cast<std::size_t>(pwd_len);
        std::vector<std::byte> pwd_bytes(
            decrypted.begin() + static_cast<ptrdiff_t>(cur),
            decrypted.begin() + static_cast<ptrdiff_t>(cur + (take ? take : pwd_max)));
        out_password_hex = BytesToHexString(std::span<const std::byte>(pwd_bytes.data(), pwd_bytes.size()));
        std::wstring candidate = ExtractUtf16(cur, pwd_len ? pwd_len : static_cast<std::uint16_t>(pwd_max));
        if (IsLikelyReadablePassword(candidate)) out_password = candidate;
    }
}

// ---------------------------------------------------------------------------

void TspkgWalker::Walk(std::vector<LogonSession>& sessions) {
    if (tmpl_ == nullptr || tmpl_->signature.empty()) return;

    const std::uint64_t sig_pos = FindSignatureInModule(
        vmem_, metadata_, L"tspkg.dll", tmpl_->signature);
    if (sig_pos == 0) return;

    const std::uint64_t entry_ref_loc =
        sig_pos + static_cast<std::int64_t>(tmpl_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(entry_ref_loc, &rel_offset)) return;
    const std::uint64_t sentinel = entry_ref_loc + 4 + static_cast<std::int64_t>(rel_offset);

    // tspkg typically maintains a single list, but probe a second candidate
    // (sentinel + 8) the same way WDigest probes 4 candidates.
    const std::vector<std::uint64_t> sentinel_candidates = {
        sentinel, sentinel + 8
    };

    std::set<std::uint64_t> processed_entries;

    for (const std::uint64_t list_sentinel : sentinel_candidates) {
        std::uint64_t current = 0;
        if (!vmem_.ReadStruct(list_sentinel, &current)) continue;
        if (current == 0 || current == list_sentinel) continue;

        int safety = 0;
        while (current != list_sentinel && safety++ < 4096) {
            if (processed_entries.count(current) != 0) {
                std::uint64_t next = 0;
                if (!vmem_.ReadStruct(current, &next)) break;
                current = next;
                continue;
            }
            processed_entries.insert(current);

            // Read LUID from template-specified offset.
            std::uint64_t entry_luid = 0;
            vmem_.ReadStruct(current + tmpl_->luid_offset, &entry_luid);

            // Read encrypted UNICODE_STRING at primary_offset.
            std::uint16_t enc_len = 0, enc_max_len = 0;
            std::uint64_t enc_buffer = 0;
            vmem_.ReadStruct(current + tmpl_->primary_offset,     &enc_len);
            vmem_.ReadStruct(current + tmpl_->primary_offset + 2, &enc_max_len);
            vmem_.ReadStruct(current + tmpl_->primary_offset + 8, &enc_buffer);

            std::wstring domain, username, password, password_hex;

            if (enc_max_len > 0 && enc_buffer != 0 &&
                extractor_ && extractor_->IsInitialized()) {
                std::vector<std::byte> enc_bytes(enc_max_len);
                if (vmem_.ReadBytes(enc_buffer, enc_max_len, enc_bytes)) {
                    auto decrypted = extractor_->Decrypt(enc_bytes);
                    ParseTspkgBlob(decrypted, tmpl_->blob_header_skip,
                                   domain, username, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        security::TspkgCredential cred;
                        cred.luid         = entry_luid;
                        cred.username     = username;
                        cred.domainname   = domain;
                        cred.password     = password;
                        cred.password_hex = password_hex;
                        s.tspkg_credentials.push_back(std::move(cred));
                        break;
                    }
                }
            }

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(current, &next)) break;
            current = next;
        }
    }
}

} // namespace KvcForensic::lsa
