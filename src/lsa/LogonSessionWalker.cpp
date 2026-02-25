#include "lsa/LogonSessionWalker.h"

#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <vector>

namespace KvcForensic::lsa {

namespace {

constexpr std::uint32_t kMinSessionCount = 2;
constexpr std::uint32_t kMaxSessionCount = 16;

std::string ComputeSha1(std::span<const std::byte> data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::string result;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (status != 0) return result;

    // Query the required hash object size at runtime
    DWORD obj_size = 0, dummy = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&obj_size), sizeof(obj_size), &dummy, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return result; }

    std::vector<BYTE> hash_object(obj_size);
    std::vector<BYTE> hash_result(20); // SHA1 always 20 bytes

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
        std::uint16_t ch = static_cast<std::uint8_t>(data[i]) | (static_cast<std::uint8_t>(data[i+1]) << 8);
        str.push_back(static_cast<wchar_t>(ch));
    }
    return str;
}

std::wstring BytesToHexString(std::span<const std::byte> bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (const auto b : bytes) {
        ss << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(b));
    }
    return ss.str();
}

bool IsLikelyReadablePassword(const std::wstring& text) {
    if (text.empty()) return false;
    if (text.size() > 512) return false;

    std::size_t printable = 0;
    for (const auto ch : text) {
        if (ch == L'\0') return false;
        if (ch == L'\r' || ch == L'\n' || ch == L'\t') {
            printable++;
            continue;
        }
        if (iswprint(ch) != 0) {
            printable++;
        }
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
    if (utf16_byte_len_hint > 0) {
        take = (std::min)(take, static_cast<std::size_t>(utf16_byte_len_hint));
    }
    if ((take & 1u) != 0u) {
        --take;
    }
    if (take == 0) return;

    const std::size_t hex_cap = (std::min)(take, static_cast<std::size_t>(4096));
    out_password_hex = BytesToHexString(std::span<const std::byte>(decrypted.data(), hex_cap));
    if (hex_cap < take) {
        out_password_hex += L"...";
    }

    std::vector<std::byte> candidate(decrypted.begin(), decrypted.begin() + take);
    std::wstring decoded = Utf16ToWString(candidate);
    while (!decoded.empty() && decoded.back() == L'\0') {
        decoded.pop_back();
    }
    if (IsLikelyReadablePassword(decoded)) {
        out_password = decoded;
    }
}

struct LSA_UNICODE_STRING {
    std::uint16_t Length;
    std::uint16_t MaximumLength;
    std::uint32_t padding; // For x64
    std::uint64_t Buffer;
};

} // namespace

LogonSessionWalker::LogonSessionWalker(const core::VirtualMemory& vmem, const minidump::MinidumpMetadata& metadata)
    : vmem_(vmem), metadata_(metadata), secrets_extractor_(std::make_unique<security::LsaSecretsExtractor>(vmem, metadata)) {}

bool LogonSessionWalker::Initialize(std::uint32_t build_number) {
    // Initialize LSA secrets extractor (AES key for credential decryption)
    if (secrets_extractor_) {
        secrets_extractor_->Initialize(build_number);
    }
    
    msv_template_ = templates::SelectMsvTemplateX64(build_number);
    wdigest_template_ = templates::SelectWdigestTemplateX64(build_number);
    kerberos_template_ = templates::SelectKerberosTemplateX64(build_number);
    dpapi_template_ = templates::SelectDpapiTemplateX64(build_number);

    if (msv_template_ == nullptr) return false;

    logon_list_va_ = FindMsvLogonList();
    if (logon_list_va_ == 0) return false;

    // For newer validated layouts we can trust template offsets directly.
    if (msv_template_->parser_support) {
        session_layout_.luid_offset = msv_template_->session_luid_offset;
        session_layout_.username_offset = msv_template_->session_username_offset;
        session_layout_.domain_offset = msv_template_->session_domain_offset;
        session_layout_.sid_ptr_offset = msv_template_->session_sid_ptr_offset;
        session_layout_.credentials_ptr_offset = msv_template_->session_credentials_ptr_offset;
    } else {
        session_layout_ = DetectSessionFieldLayout();
    }

    return session_layout_.luid_offset != 0 && session_layout_.credentials_ptr_offset != 0;
}

std::uint64_t LogonSessionWalker::FindMsvLogonList() {
    if (msv_template_ == nullptr || msv_template_->signature.empty()) return 0;

    const minidump::ModuleInfo* lsasrv_mod = nullptr;
    for (const auto& mod : metadata_.modules) {
        std::wstring name_lower = mod.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::towlower);
        if (name_lower.find(L"lsasrv.dll") != std::wstring::npos) {
            lsasrv_mod = &mod;
            break;
        }
    }
    
    if (!lsasrv_mod) return 0;

    const auto& sig = msv_template_->signature;
    std::uint64_t pos = 0;

    for (const auto& range : metadata_.memory_ranges) {
        std::uint64_t start = (std::max)(range.start_vva, static_cast<std::uint64_t>(lsasrv_mod->base_address));
        std::uint64_t end = (std::min)(range.start_vva + range.size, static_cast<std::uint64_t>(lsasrv_mod->base_address + lsasrv_mod->size));
        
        if (start < end && (end - start) >= sig.size()) {
            std::vector<std::byte> chunk(end - start);
            if (vmem_.ReadBytes(start, chunk.size(), chunk)) {
                // FindPattern manually to handle offset 0 correctly
                for (std::size_t i = 0; i <= chunk.size() - sig.size(); ++i) {
                    if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0) {
                        pos = start + i;
                        break;
                    }
                }
                if (pos != 0) break;
            }
        }
    }
    
    if (pos == 0) return 0;
    
    // ptr_entry_loc = get_ptr_with_offset(pos + first_entry_offset) + first_entry_offset_correction
    const std::uint64_t ptr_to_rel_offset =
        pos + static_cast<std::int64_t>(msv_template_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(ptr_to_rel_offset, &rel_offset)) return 0;
    
    std::uint64_t ptr_entry_loc = ptr_to_rel_offset + 4 + rel_offset;
    
    if (msv_template_->first_entry_offset_correction > 0) {
        std::uint32_t additional_offset = 0;
        const auto corr_loc = pos + static_cast<std::int64_t>(msv_template_->first_entry_offset_correction);
        if (vmem_.ReadStruct(corr_loc, &additional_offset)) {
            ptr_entry_loc += additional_offset;
        }
    }
    
    ptr_entry_loc_ = ptr_entry_loc;

    // Read session count from template offset2, when available.
    if (msv_template_->offset2 != 0) {
        const std::uint64_t count_ptr_loc =
            pos + static_cast<std::int64_t>(msv_template_->offset2);
        std::int32_t count_rel_offset = 0;
        if (vmem_.ReadStruct(count_ptr_loc, &count_rel_offset)) {
            const std::uint64_t count_loc = count_ptr_loc + 4 + count_rel_offset;
            std::uint8_t count = 0;
            if (vmem_.ReadStruct(count_loc, &count)) {
                session_count_ = count;
                if (session_count_ == 0) session_count_ = 1;
            }
        }
    }
    
    // Clamp list count to a defensive range for malformed dumps.
    if (session_count_ < kMinSessionCount) session_count_ = kMinSessionCount;
    if (session_count_ > kMaxSessionCount) session_count_ = kMaxSessionCount;

    std::uint64_t target_list = 0;
    if (!vmem_.ReadStruct(ptr_entry_loc, &target_list)) return 0;

    return target_list;
}

LogonSessionWalker::SessionFieldLayout LogonSessionWalker::DetectSessionFieldLayout() {
    struct Candidate {
        SessionFieldLayout layout;
    };
    // x64 variants observed across MSV list generations; scored against actual memory.
    const std::array<Candidate, 6> candidates{{
        { {0x70, 0xA0, 0xB0, 0xE0, 0x118} }, // 24H2/25H2
        { {0x68, 0x98, 0xA8, 0xD8, 0x110} },
        { {0x60, 0x90, 0xA0, 0xD0, 0x108} },
        { {0x58, 0x88, 0x98, 0xC8, 0x100} },
        { {0x50, 0x80, 0x90, 0xC0, 0xF8} },
        { {0x48, 0x78, 0x88, 0xB8, 0xF0} },
    }};

    auto score_candidate = [&](const SessionFieldLayout& f) -> int {
        int score = 0;
        int samples = 0;

        for (std::uint32_t i = 0; i < session_count_ && i < 4; ++i) {
            std::uint64_t skip_ptr = ptr_entry_loc_ + (static_cast<std::uint64_t>(i) * 16);
            std::uint64_t list_head = 0;
            if (!vmem_.ReadStruct(skip_ptr, &list_head) || list_head == 0) continue;

            std::vector<std::uint64_t> visited;
            std::uint64_t current = list_head;
            for (int n = 0; n < 8; ++n) {
                if (current == 0 || std::find(visited.begin(), visited.end(), current) != visited.end()) break;
                visited.push_back(current);
                samples++;

                std::uint64_t luid = 0;
                if (vmem_.ReadStruct(current + f.luid_offset, &luid) && luid != 0) {
                    score += 3;
                }

                const std::wstring user = ReadUnicodeString(current + f.username_offset);
                const std::wstring dom = ReadUnicodeString(current + f.domain_offset);
                if (!user.empty() || !dom.empty()) {
                    score += 2;
                }

                std::uint64_t sid_ptr = 0;
                if (vmem_.ReadStruct(current + f.sid_ptr_offset, &sid_ptr) && sid_ptr != 0) {
                    const auto sid = ReadSid(sid_ptr);
                    if (sid.rfind("S-1-", 0) == 0) score += 2;
                }

                std::uint64_t creds_ptr = 0;
                if (vmem_.ReadStruct(current + f.credentials_ptr_offset, &creds_ptr)) {
                    score += 1;
                }

                std::uint64_t next = 0;
                if (!vmem_.ReadStruct(current, &next) || next == list_head) break;
                current = next;
            }
        }

        if (samples == 0) return -1;
        return score;
    };

    SessionFieldLayout best{};
    int best_score = -1;
    for (const auto& c : candidates) {
        const int sc = score_candidate(c.layout);
        if (sc > best_score) {
            best_score = sc;
            best = c.layout;
        }
    }

    // Last fallback to newest known offsets.
    if (best.luid_offset == 0) {
        best = {0x70, 0xA0, 0xB0, 0xE0, 0x118};
    }
    return best;
}

std::wstring LogonSessionWalker::ReadUnicodeString(std::uint64_t string_va) {
    LSA_UNICODE_STRING ustr;
    if (!vmem_.ReadStruct(string_va, &ustr)) return L"";
    
    if (ustr.Length == 0 || ustr.Buffer == 0) return L"";
    
    // Security limit: max string length 512 chars
    std::uint16_t safe_len = (std::min)(ustr.Length, static_cast<std::uint16_t>(1024));
    std::vector<std::byte> buffer(safe_len);
    if (!vmem_.ReadBytes(ustr.Buffer, safe_len, buffer)) return L"";
    
    return Utf16ToWString(buffer);
}

std::string LogonSessionWalker::ReadSid(std::uint64_t sid_va) {
    if (sid_va == 0) return "None";
    
    std::uint8_t revision = 0;
    if (!vmem_.ReadStruct(sid_va, &revision)) return "None";
    
    std::uint8_t sub_authority_count = 0;
    if (!vmem_.ReadStruct(sid_va + 1, &sub_authority_count)) return "None";
    
    // Limit sub-authorities to 15 (MAX_SID_SUBAUTHORITIES)
    if (sub_authority_count > 15) sub_authority_count = 15;

    std::vector<std::uint8_t> identifier_authority(6);
    if (!vmem_.ReadBytes(sid_va + 2, 6, std::span<std::byte>(reinterpret_cast<std::byte*>(identifier_authority.data()), 6))) return "None";
    
    std::uint64_t auth = 0;
    for (int i=0; i<6; ++i) {
        auth = (auth << 8) | identifier_authority[i];
    }
    
    std::ostringstream ss;
    ss << "S-" << static_cast<int>(revision) << "-" << auth;
    
    for (int i=0; i<sub_authority_count; ++i) {
        std::uint32_t sub_auth = 0;
        if (!vmem_.ReadStruct(sid_va + 8 + (i * 4), &sub_auth)) break;
        ss << "-" << sub_auth;
    }
    
    return ss.str();
}

std::vector<LogonSession> LogonSessionWalker::Walk() {
    std::vector<LogonSession> sessions;
    if (logon_list_va_ == 0 || ptr_entry_loc_ == 0) return sessions;

    for (std::uint32_t i = 0; i < session_count_; ++i) {
        // Skip i*2 pointers (each pointer is 8 bytes).
        std::uint64_t skip_ptr = ptr_entry_loc_ + static_cast<std::uint64_t>(i) * 16;
        
        // Read the actual list head pointer
        std::uint64_t list_head = 0;
        if (!vmem_.ReadStruct(skip_ptr, &list_head)) {
            continue;
        }
        
        if (list_head == 0) continue;

        std::uint64_t current = 0;
        if (!vmem_.ReadStruct(list_head, &current)) continue;

        // Check if list is empty (head points to itself)
        if (current == list_head) continue;

        std::vector<std::uint64_t> visited;

        std::uint64_t walk_start = list_head;
        
        do {
            if (walk_start == 0) break;
            if (std::find(visited.begin(), visited.end(), walk_start) != visited.end()) {
                break; // Loop detected
            }
            visited.push_back(walk_start);

            LogonSession session;
            session.address = walk_start;

            std::uint64_t luid = 0;
            if (vmem_.ReadStruct(walk_start + session_layout_.luid_offset, &luid)) {
                session.authentication_id = luid;
            }

            session.username = ReadUnicodeString(walk_start + session_layout_.username_offset);
            session.domainname = ReadUnicodeString(walk_start + session_layout_.domain_offset);

            std::uint64_t psid_ptr = 0;
            if (vmem_.ReadStruct(walk_start + session_layout_.sid_ptr_offset, &psid_ptr) && psid_ptr != 0) {
                session.sid = ReadSid(psid_ptr);
            }
            
            std::uint64_t creds_ptr = 0;
            if (vmem_.ReadStruct(walk_start + session_layout_.credentials_ptr_offset, &creds_ptr)) {
                session.credentials_list_ptr = creds_ptr;
            }

            // Skip sessions with LUID 0 (invalid)
            if (session.authentication_id == 0) {
                std::uint64_t next = 0;
                if (!vmem_.ReadStruct(walk_start, &next)) break;
                walk_start = next;
                continue;
            }

            sessions.push_back(session);

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(walk_start, &next)) break;
            walk_start = next;
        } while (walk_start != 0 && walk_start != list_head);
    }

    return sessions;
}

void LogonSessionWalker::ExtractCredentials(LogonSession& session) {
    if (session.credentials_list_ptr == 0) return;

    // Sentinel = address of credentials_ptr field in selected list layout.
    std::uint64_t sentinel = session.address + session_layout_.credentials_ptr_offset;
    WalkCredentialsList(session.credentials_list_ptr, sentinel, session.msv_credentials);
}

void LogonSessionWalker::WalkCredentialsList(
    std::uint64_t credentials_list_ptr,
    std::uint64_t sentinel,
    std::vector<security::MsvCredential>& creds) {

    if (credentials_list_ptr == 0) return;

    std::vector<std::uint64_t> visited;
    visited.push_back(sentinel); // Mark sentinel as visited so we stop if Flink points back
    std::uint64_t current = credentials_list_ptr;

    while (current != 0 && current != sentinel) {
        if (std::find(visited.begin(), visited.end(), current) != visited.end()) {
            break;
        }
        visited.push_back(current);

        // Read KIWI_MSV1_0_CREDENTIAL_LIST structure
        std::uint64_t flink = 0;
        std::uint32_t auth_pkg_id = 0;

        if (!vmem_.ReadStruct(current, &flink)) break;
        if (!vmem_.ReadStruct(current + 8, &auth_pkg_id)) break;

        // PrimaryCredentials_ptr at offset 16
        std::uint64_t primary_ptr = 0;
        if (!vmem_.ReadStruct(current + 16, &primary_ptr)) break;

        // Walk primary credentials; sentinel = address of PrimaryCredentials_ptr field
        if (primary_ptr != 0) {
            WalkPrimaryCredentials(primary_ptr, current + 16, creds);
        }

        current = flink;
    }
}

void LogonSessionWalker::WalkPrimaryCredentials(
    std::uint64_t primary_ptr,
    std::uint64_t sentinel,
    std::vector<security::MsvCredential>& creds) {

    if (primary_ptr == 0) return;

    std::vector<std::uint64_t> visited;
    visited.push_back(sentinel);
    std::uint64_t current = primary_ptr;

    while (current != 0 && current != sentinel) {
        if (std::find(visited.begin(), visited.end(), current) != visited.end()) {
            break;
        }
        visited.push_back(current);

        // Read KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC structure
        std::uint64_t flink = 0;
        std::uint16_t enc_len = 0;
        std::uint16_t enc_max_len = 0;
        std::uint64_t enc_buffer = 0;

        if (!vmem_.ReadStruct(current, &flink)) break;

        // LSA_UNICODE_STRING at offset 24
        if (!vmem_.ReadStruct(current + 24, &enc_len)) break;
        if (!vmem_.ReadStruct(current + 26, &enc_max_len)) break;
        if (!vmem_.ReadStruct(current + 32, &enc_buffer)) break;
        if (enc_max_len != 0 && enc_len > enc_max_len) {
            current = flink;
            continue;
        }

        // Read encrypted credentials data (x64 addresses are above 0xFFFFFFFF)
        if (enc_len > 0 && enc_buffer != 0) {
            std::vector<std::byte> encrypted_data(enc_len);
            if (vmem_.ReadBytes(enc_buffer, enc_len, encrypted_data)) {
                auto cred = DecryptPrimaryCredential(encrypted_data);
                if (!cred.username.empty() || !cred.nt_hash.empty() || !cred.dpapi.empty()) {
                    creds.push_back(cred);
                }
            }
        }

        current = flink;
    }
}

security::MsvCredential LogonSessionWalker::DecryptPrimaryCredential(
    std::span<const std::byte> encrypted_data) {

    security::MsvCredential cred;

    if (encrypted_data.empty()) return cred;

    // Initialize secrets extractor if not already done
    if (secrets_extractor_ && secrets_extractor_->IsInitialized()) {
        // Try to decrypt using AES-CFB
        auto decrypted = secrets_extractor_->Decrypt(encrypted_data);
        if (!decrypted.empty() && decrypted.size() >= 88) {
            // Successfully decrypted - parse structure
            std::uint16_t username_len = 0;
            std::uint64_t username_buffer = 0;
            std::uint16_t domain_len = 0;
            std::uint64_t domain_buffer = 0;
            std::uint8_t is_dpapi_protected = 0;
            std::uint8_t is_nt = 0;
            std::uint8_t is_sha = 0;
            std::uint8_t is_dpapi = 0;

            // Parse header
            std::memcpy(&username_len,   decrypted.data() + 16, 2);
            std::memcpy(&username_buffer, decrypted.data() + 24, 8);
            std::memcpy(&domain_len,     decrypted.data(),      2);
            std::memcpy(&domain_buffer,  decrypted.data() + 8,  8);

            // MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC flag layout (empirically verified, build 26100+):
            //   [40] isDPAPIProtected  — format discriminator: 0=Format A, 1=Format B
            //   [41] isNtOwfPassword
            //   [42] isLmOwfPassword
            //   [43] isShaOwfPassword
            //   [44] isDPAPILimitedKey (subtype / count)
            //
            // Format A (isDPAPIProtected=0):
            //   [50..69]  DPAPILimitedKey (20 B)
            //   [70..85]  NtOwfPassword   (16 B)
            //   [86..101] LmOwfPassword   (16 B, usually zero)
            //   [102..121] ShaOwfPassword (20 B)
            //
            // Format B (isDPAPIProtected=1):
            //   [50..65]  NtOwfPassword   (16 B)   ← moved earlier
            //   [102..121] ShaOwfPassword (20 B)   ← unchanged
            //   [122..141] DPAPILimitedKey (20 B)  ← appended after SHA1
            is_dpapi_protected = static_cast<std::uint8_t>(decrypted[40]);
            is_nt    = static_cast<std::uint8_t>(decrypted[41]);
            is_sha   = static_cast<std::uint8_t>(decrypted[43]);
            is_dpapi = static_cast<std::uint8_t>(decrypted[44]);

            // Read username
            if (username_len > 0 && username_buffer != 0) {
                std::vector<std::byte> username_bytes(username_len);
                if (vmem_.ReadBytes(username_buffer, username_len, username_bytes)) {
                    cred.username = Utf16ToWString(username_bytes);
                }
            }

            // Read domain
            if (domain_len > 0 && domain_buffer != 0) {
                std::vector<std::byte> domain_bytes(domain_len);
                if (vmem_.ReadBytes(domain_buffer, domain_len, domain_bytes)) {
                    cred.domainname = Utf16ToWString(domain_bytes);
                }
            }

            if (is_dpapi_protected == 0) {
                // Format A: standard layout
                if (is_dpapi && decrypted.size() >= 70) {
                    cred.dpapi.assign(decrypted.begin() + 50, decrypted.begin() + 70);
                }
                if (is_nt && decrypted.size() >= 86) {
                    cred.nt_hash.assign(decrypted.begin() + 70, decrypted.begin() + 86);
                }
                if (is_sha && decrypted.size() >= 122) {
                    cred.sha1_hash.assign(decrypted.begin() + 102, decrypted.begin() + 122);
                }
            } else {
                // Format B: isDPAPIProtected=1, NT hash at [50..65]
                if (is_nt && decrypted.size() >= 66) {
                    cred.nt_hash.assign(decrypted.begin() + 50, decrypted.begin() + 66);
                }
                if (is_sha && decrypted.size() >= 122) {
                    cred.sha1_hash.assign(decrypted.begin() + 102, decrypted.begin() + 122);
                }
                if (is_dpapi && decrypted.size() >= 142) {
                    cred.dpapi.assign(decrypted.begin() + 122, decrypted.begin() + 142);
                }
            }

            return cred;
        } else if (!decrypted.empty()) {
            // Decrypted payload too short to parse the expected credential layout.
            // Keep consistent behavior with fallback path below by preserving raw bytes.
            cred.dpapi.assign(encrypted_data.begin(), encrypted_data.end());
            return cred;
        }
    }
    
    // Fallback: store encrypted data
    cred.dpapi.assign(encrypted_data.begin(), encrypted_data.end());
    return cred;
}

std::uint64_t LogonSessionWalker::FindSignatureInModule(
    const std::wstring& module_name,
    const std::vector<std::uint8_t>& sig) {

    const minidump::ModuleInfo* mod = nullptr;
    for (const auto& m : metadata_.modules) {
        std::wstring name_lower = m.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::towlower);
        std::wstring search_lower = module_name;
        std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(), ::towlower);
        if (name_lower.find(search_lower) != std::wstring::npos) {
            mod = &m;
            break;
        }
    }
    if (!mod) return 0;

    for (const auto& range : metadata_.memory_ranges) {
        std::uint64_t start = (std::max)(range.start_vva, static_cast<std::uint64_t>(mod->base_address));
        std::uint64_t end = (std::min)(range.start_vva + range.size,
                                       static_cast<std::uint64_t>(mod->base_address + mod->size));
        if (start >= end || (end - start) < sig.size()) continue;

        std::vector<std::byte> chunk(end - start);
        if (!vmem_.ReadBytes(start, chunk.size(), chunk)) continue;

        for (std::size_t i = 0; i <= chunk.size() - sig.size(); ++i) {
            if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0) {
                return start + i;
            }
        }
    }
    return 0;
}

void LogonSessionWalker::ExtractCredmanCredentials(LogonSession& session) {
    // CredentialManager PVOID at session + 0x168
    std::uint64_t cred_manager_ptr = 0;
    if (!vmem_.ReadStruct(session.address + 0x168, &cred_manager_ptr)) return;
    if (cred_manager_ptr == 0) return;

    // KIWI_CREDMAN_SET_LIST_ENTRY: Flink(8)+Blink(8)+unk0(4)+align(4)+list1(8)
    // list1 ptr at offset +24
    std::uint64_t list1_ptr = 0;
    if (!vmem_.ReadStruct(cred_manager_ptr + 24, &list1_ptr)) return;
    if (list1_ptr == 0) return;

    // KIWI_CREDMAN_LIST_STARTER: unk0(4)+align(4)+start(8)
    // start ptr at offset +8; sentinel = list1_ptr+8 (location of start field)
    std::uint64_t sentinel = list1_ptr + 8;
    std::uint64_t current_flink = 0;
    if (!vmem_.ReadStruct(sentinel, &current_flink)) return;
    if (current_flink == sentinel) return;  // empty list

    int safety = 0;
    while (current_flink != sentinel && safety++ < 255) {
        // Entry struct starts 56 bytes before the Flink field
        std::uint64_t entry_start = current_flink - 56;

        // cbEncPassword at entry_start+0 (DWORD)
        std::uint32_t cb_enc_password = 0;
        vmem_.ReadStruct(entry_start, &cb_enc_password);

        // encPassword_ptr at entry_start+8 (PVOID)
        std::uint64_t enc_password_ptr = 0;
        vmem_.ReadStruct(entry_start + 8, &enc_password_ptr);

        // user LSA_UNICODE_STRING at entry_start+168
        std::wstring username = ReadUnicodeString(entry_start + 168);
        // server2 LSA_UNICODE_STRING at entry_start+192
        std::wstring domainname = ReadUnicodeString(entry_start + 192);

        std::wstring password;
        std::wstring password_hex;
        if (cb_enc_password > 0 && enc_password_ptr != 0 &&
            secrets_extractor_ && secrets_extractor_->IsInitialized()) {
            std::vector<std::byte> enc_bytes(cb_enc_password);
            if (vmem_.ReadBytes(enc_password_ptr, cb_enc_password, enc_bytes)) {
                auto dec = secrets_extractor_->Decrypt(enc_bytes);
                DecodePasswordCandidate(dec, 0, password, password_hex);
            }
        }

        if (!username.empty() || !domainname.empty() || !password.empty() || !password_hex.empty()) {
            security::CredmanCredential cred;
            cred.username = username;
            cred.domainname = domainname;
            cred.password = password;
            cred.password_hex = password_hex;
            session.credman_credentials.push_back(cred);
        }

        std::uint64_t next = 0;
        if (!vmem_.ReadStruct(current_flink, &next)) break;
        current_flink = next;
    }
}

void LogonSessionWalker::WalkWdigestList(std::vector<LogonSession>& sessions) {
    if (wdigest_template_ == nullptr || wdigest_template_->signature.empty()) return;

    std::uint64_t sig_pos = FindSignatureInModule(L"wdigest.dll", wdigest_template_->signature);
    if (sig_pos == 0) return;

    // GetPtrWithOffset(sig_pos + first_entry_offset)
    const std::uint64_t entry_ref_loc =
        sig_pos + static_cast<std::int64_t>(wdigest_template_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(entry_ref_loc, &rel_offset)) return;
    std::uint64_t sentinel = entry_ref_loc + 4 + static_cast<std::int64_t>(rel_offset);

    // On some builds WDigest keeps multiple adjacent list heads. Walk both candidates
    // and deduplicate by entry address to avoid counting the same node twice.
    std::set<std::uint64_t> processed_entries;
    std::vector<std::uint64_t> sentinel_candidates = {
        sentinel, sentinel + 8, sentinel + 16, sentinel + 24
    };

    for (std::uint64_t list_sentinel : sentinel_candidates) {
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

            // LUID at current+32 (after Flink(8)+Blink(8)+usage_count(4)+align(4)+this_entry(8))
            std::uint64_t entry_luid = 0;
            vmem_.ReadStruct(current + 32, &entry_luid);

            // Credentials start at template primary offset.
            const std::size_t po = wdigest_template_->primary_offset;
            std::wstring username   = ReadUnicodeString(current + po);
            std::wstring domainname = ReadUnicodeString(current + po + 16);

            // Password LSA_UNICODE_STRING at current+80; use MaximumLength for encrypted size
            std::uint16_t pwd_len = 0, pwd_max_len = 0;
            std::uint64_t pwd_buffer = 0;
            vmem_.ReadStruct(current + po + 32, &pwd_len);
            vmem_.ReadStruct(current + po + 34, &pwd_max_len);
            vmem_.ReadStruct(current + po + 40, &pwd_buffer);

            std::wstring password;
            std::wstring password_hex;
            if (pwd_max_len > 0 && pwd_buffer != 0 &&
                secrets_extractor_ && secrets_extractor_->IsInitialized()) {
                std::vector<std::byte> enc_bytes(pwd_max_len);
                if (vmem_.ReadBytes(pwd_buffer, pwd_max_len, enc_bytes)) {
                    auto dec = secrets_extractor_->Decrypt(enc_bytes);
                    DecodePasswordCandidate(dec, pwd_len, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        security::WdigestCredential cred;
                        cred.luid       = entry_luid;
                        cred.username   = username;
                        cred.domainname = domainname;
                        cred.password   = password;
                        cred.password_hex = password_hex;
                        s.wdigest_credentials.push_back(cred);
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

void LogonSessionWalker::WalkKerberosAvl(std::vector<LogonSession>& sessions) {
    if (kerberos_template_ == nullptr || kerberos_template_->signature.empty()) return;

    std::uint64_t sig_pos = FindSignatureInModule(L"kerberos.dll", kerberos_template_->signature);
    if (sig_pos == 0) return;

    // GetPtrWithOffset(sig_pos + first_entry_offset)
    const std::uint64_t entry_ref_loc =
        sig_pos + static_cast<std::int64_t>(kerberos_template_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(entry_ref_loc, &rel_offset)) return;
    std::uint64_t avl_table_loc = entry_ref_loc + 4 + static_cast<std::int64_t>(rel_offset);

    // Dereference to get the RTL_AVL_TABLE pointer
    std::uint64_t avl_table_ptr = 0;
    if (!vmem_.ReadStruct(avl_table_loc, &avl_table_ptr)) return;
    if (avl_table_ptr == 0) return;

    // RTL_AVL_TABLE.BalancedRoot.RightChild at offset +16 = root of the tree
    std::uint64_t root = 0;
    if (!vmem_.ReadStruct(avl_table_ptr + 16, &root)) return;
    if (root == 0) return;

    std::set<std::uint64_t> visited;
    WalkAvlNode(root, avl_table_ptr, sessions, visited);
}

void LogonSessionWalker::WalkAvlNode(
    std::uint64_t node_addr,
    std::uint64_t table_addr,
    std::vector<LogonSession>& sessions,
    std::set<std::uint64_t>& visited) {
    if (node_addr == 0 || node_addr == table_addr) return;

    std::vector<std::uint64_t> stack;
    stack.push_back(node_addr);

    while (!stack.empty()) {
        const std::uint64_t current = stack.back();
        stack.pop_back();

        if (current == 0 || current == table_addr) continue;
        if (visited.count(current)) continue;
        visited.insert(current);

        // RTL_BALANCED_LINKS (32 bytes): Parent(8)+LeftChild(8)+RightChild(8)+Balance(1)+Reserved(3)+pad(4)
        // OrderedPointer (session ptr) at node+32
        std::uint64_t session_ptr = 0;
        vmem_.ReadStruct(current + 32, &session_ptr);

        if (session_ptr != 0) {
            auto luid_exists = [&](const std::uint64_t luid) -> bool {
                if (luid == 0) return false;
                for (const auto& s : sessions) {
                    if (s.authentication_id == luid) return true;
                }
                return false;
            };

            std::uint64_t entry_luid = 0;
            vmem_.ReadStruct(session_ptr + kerberos_template_->session_luid_offset, &entry_luid);
            if (!luid_exists(entry_luid)) {
                for (const auto off : kerberos_template_->session_luid_fallback_offsets) {
                    std::uint64_t alt_luid = 0;
                    if (vmem_.ReadStruct(session_ptr + off, &alt_luid) && luid_exists(alt_luid)) {
                        entry_luid = alt_luid;
                        break;
                    }
                }
            }

            std::wstring username = ReadUnicodeString(session_ptr + kerberos_template_->session_username_offset);
            std::wstring domainname = ReadUnicodeString(session_ptr + kerberos_template_->session_domain_offset);

            std::uint16_t pwd_len = 0, pwd_max_len = 0;
            std::uint64_t pwd_buffer = 0;
            const auto pwd_off = kerberos_template_->session_password_ustr_offset;
            vmem_.ReadStruct(session_ptr + pwd_off, &pwd_len);
            vmem_.ReadStruct(session_ptr + pwd_off + 2, &pwd_max_len);
            vmem_.ReadStruct(session_ptr + pwd_off + 8, &pwd_buffer);

            std::wstring password;
            std::wstring password_hex;
            if (pwd_max_len > 0 && pwd_buffer != 0 &&
                secrets_extractor_ && secrets_extractor_->IsInitialized()) {
                std::vector<std::byte> enc_bytes(pwd_max_len);
                if (vmem_.ReadBytes(pwd_buffer, pwd_max_len, enc_bytes)) {
                    auto dec = secrets_extractor_->Decrypt(enc_bytes);
                    DecodePasswordCandidate(dec, pwd_len, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        security::KerberosCredential cred;
                        cred.luid       = entry_luid;
                        cred.username   = username;
                        cred.domainname = domainname;
                        cred.password   = password;
                        cred.password_hex = password_hex;
                        
                        WalkKerberosTickets(session_ptr, cred);
                        
                        s.kerberos_credentials.push_back(cred);
                        break;
                    }
                }
            }
        }

        // Push children (right first so left is processed first).
        std::uint64_t left_child = 0, right_child = 0;
        vmem_.ReadStruct(current + 8, &left_child);
        vmem_.ReadStruct(current + 16, &right_child);
        if (right_child != 0 && right_child != table_addr && !visited.count(right_child)) {
            stack.push_back(right_child);
        }
        if (left_child != 0 && left_child != table_addr && !visited.count(left_child)) {
            stack.push_back(left_child);
        }
    }
}

void LogonSessionWalker::WalkKerberosTickets(std::uint64_t session_ptr, security::KerberosCredential& cred) {
    if (kerberos_template_ == nullptr || kerberos_template_->ticket_list_offsets.empty()) {
        return;
    }

    for (const std::size_t ticket_offset : kerberos_template_->ticket_list_offsets) {
        std::uint64_t flink = 0;
        if (!vmem_.ReadStruct(session_ptr + ticket_offset, &flink)) continue;

        const std::uint64_t list_head = session_ptr + ticket_offset;
        if (flink == 0 || flink == list_head || flink == list_head - 4) continue;

        std::uint64_t current = flink;
        std::set<std::uint64_t> visited;

        while (current != 0 && current != list_head) {
            if (visited.count(current)) break;
            visited.insert(current);

            std::uint64_t service_name_ptr = 0;
            std::uint64_t target_name_ptr  = 0;
            std::uint64_t client_name_ptr  = 0;
            std::uint32_t ticket_flags     = 0;
            std::uint32_t key_type         = 0;
            std::uint32_t ticket_enc_type  = 0;
            std::uint32_t ticket_kvno      = 0;
            std::uint32_t ticket_len       = 0;
            std::uint64_t ticket_buffer    = 0;

            vmem_.ReadStruct(current + kerberos_template_->ticket_service_name_offset, &service_name_ptr);
            vmem_.ReadStruct(current + kerberos_template_->ticket_target_name_offset, &target_name_ptr);
            vmem_.ReadStruct(current + kerberos_template_->ticket_client_name_offset, &client_name_ptr);
            vmem_.ReadStruct(current + kerberos_template_->ticket_flags_offset, &ticket_flags);
            vmem_.ReadStruct(current + kerberos_template_->ticket_key_type_offset, &key_type);
            vmem_.ReadStruct(current + kerberos_template_->ticket_enc_type_offset, &ticket_enc_type);
            vmem_.ReadStruct(current + kerberos_template_->ticket_kvno_offset, &ticket_kvno);
            vmem_.ReadStruct(current + kerberos_template_->ticket_buffer_len_offset, &ticket_len);
            vmem_.ReadStruct(current + kerberos_template_->ticket_buffer_ptr_offset, &ticket_buffer);

            std::wstring service_name;
            std::wstring target_name;
            std::wstring client_name;
            const auto ext_name_off = kerberos_template_->external_name_first_string_offset;
            if (service_name_ptr != 0) service_name = ReadUnicodeString(service_name_ptr + ext_name_off);
            if (target_name_ptr  != 0) target_name = ReadUnicodeString(target_name_ptr + ext_name_off);
            if (client_name_ptr  != 0) client_name = ReadUnicodeString(client_name_ptr + ext_name_off);

            if (ticket_len > 0 && ticket_len < 0x10000 && ticket_buffer != 0) {
                std::vector<std::byte> ticket_data(ticket_len);
                if (vmem_.ReadBytes(ticket_buffer, ticket_len, ticket_data)) {
                    security::KerberosTicket t;
                    t.service_name = service_name;
                    t.target_name  = target_name;
                    t.client_name  = client_name;
                    t.flags        = ticket_flags;
                    t.enc_type     = ticket_enc_type;
                    t.kvno         = ticket_kvno;
                    t.data         = std::move(ticket_data);
                    cred.tickets.push_back(std::move(t));
                }
            }

            std::uint64_t next_flink = 0;
            if (!vmem_.ReadStruct(current, &next_flink)) break;
            current = next_flink;
        }
    }
}

void LogonSessionWalker::WalkDpapiList(std::vector<LogonSession>& sessions) {
    if (dpapi_template_ == nullptr || dpapi_template_->signature.empty()) return;

    // Collect all candidate sig positions from named modules, then all memory.
    // The signature 48 89 4F 08 48 89 78 08 appears multiple times in lsasrv.dll;
    // we must find the occurrence whose RIP-relative sentinel is readable.
    const auto& sig = dpapi_template_->signature;
    const int feo = dpapi_template_->first_entry_offset;

    // Helper: collect all occurrences of sig within a module's mapped VA ranges.
    auto collect_in_module = [&](const std::wstring& module_name,
                                  std::vector<std::uint64_t>& out) {
        const minidump::ModuleInfo* mod = nullptr;
        for (const auto& m : metadata_.modules) {
            std::wstring nl = m.name, sl = module_name;
            std::transform(nl.begin(), nl.end(), nl.begin(), ::towlower);
            std::transform(sl.begin(), sl.end(), sl.begin(), ::towlower);
            if (nl.find(sl) != std::wstring::npos) { mod = &m; break; }
        }
        if (!mod) return;
        for (const auto& range : metadata_.memory_ranges) {
            std::uint64_t start = (std::max)(range.start_vva, static_cast<std::uint64_t>(mod->base_address));
            std::uint64_t end   = (std::min)(range.start_vva + range.size,
                                             static_cast<std::uint64_t>(mod->base_address + mod->size));
            if (start >= end || (end - start) < sig.size()) continue;
            std::vector<std::byte> chunk(end - start);
            if (!vmem_.ReadBytes(start, chunk.size(), chunk)) continue;
            for (std::size_t i = 0; i + sig.size() <= chunk.size(); ++i) {
                if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0)
                    out.push_back(start + i);
            }
        }
    };

    // Collect all candidate sig positions from named modules, fall back to all memory.
    // The signature appears multiple times; EVERY valid sentinel must be walked because
    // different sentinels may cover different LUIDs.
    std::vector<std::uint64_t> all_candidates;
    collect_in_module(L"lsasrv.dll",   all_candidates);
    collect_in_module(L"dpapisrv.dll",  all_candidates);
    collect_in_module(L"lsass.exe",     all_candidates);

    if (all_candidates.empty()) {
        constexpr std::size_t kMaxFallbackRangeBytes = 64u * 1024 * 1024; // 64 MB guard
        for (const auto& range : metadata_.memory_ranges) {
            if (range.size < sig.size() || range.size > kMaxFallbackRangeBytes) continue;
            std::vector<std::byte> chunk(range.size);
            if (!vmem_.ReadBytes(range.start_vva, chunk.size(), chunk)) continue;
            for (std::size_t i = 0; i + sig.size() <= chunk.size(); ++i) {
                if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0)
                    all_candidates.push_back(range.start_vva + i);
            }
        }
    }

    if (all_candidates.empty()) return;

    // Lambda: walk one KIWI_MASTERKEY_CACHE_ENTRY linked list from sentinel.
    // visited_entries prevents processing the same physical entry twice across lists.
    std::set<std::uint64_t> visited_entries;

    auto walk_one_list = [&](std::uint64_t sentinel, std::uint64_t first) {
        std::uint64_t current = first;
        int safety = 0;
        while (current != sentinel && current != 0 && safety++ < 4096) {
            if (visited_entries.count(current)) break;
            visited_entries.insert(current);

            // KIWI_MASTERKEY_CACHE_ENTRY:
            // Flink(8)+Blink(8)+LogonId(8 @+16)+KeyUid(16 @+24)+insertTime(8 @+40)+keySize(4 @+48)+key(@+52)
            std::uint64_t luid = 0;
            if (!vmem_.ReadStruct(current + 16, &luid)) break;

            std::vector<std::byte> guid_bytes(16);
            if (!vmem_.ReadBytes(current + 24, 16, guid_bytes)) break;

            std::uint32_t data1 = 0; std::uint16_t data2 = 0, data3 = 0;
            std::memcpy(&data1, guid_bytes.data(), 4);
            std::memcpy(&data2, guid_bytes.data() + 4, 2);
            std::memcpy(&data3, guid_bytes.data() + 6, 2);
            std::stringstream guid_ss;
            guid_ss << std::hex << std::setfill('0')
                    << std::setw(8) << data1 << "-"
                    << std::setw(4) << data2 << "-"
                    << std::setw(4) << data3 << "-";
            for (int i = 8; i < 16; ++i) {
                guid_ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(guid_bytes[i]));
                if (i == 9) guid_ss << "-";
            }
            std::string key_guid = guid_ss.str();

            std::uint32_t key_size = 0;
            if (!vmem_.ReadStruct(current + 48, &key_size)) break;

            std::vector<std::byte> masterkey_encrypted;
            if (key_size > 0 && key_size < 512) {
                masterkey_encrypted.resize(key_size);
                if (!vmem_.ReadBytes(current + 52, key_size, masterkey_encrypted))
                    masterkey_encrypted.clear();
            }

            std::vector<std::byte> masterkey_decrypted;
            std::string sha1_masterkey;
            if (!masterkey_encrypted.empty() && secrets_extractor_ && secrets_extractor_->IsInitialized()) {
                masterkey_decrypted = secrets_extractor_->Decrypt(masterkey_encrypted);
                if (!masterkey_decrypted.empty())
                    sha1_masterkey = ComputeSha1(masterkey_decrypted);
            }

            if (luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == luid) {
                        security::DpapiCredential cred;
                        cred.luid           = luid;
                        cred.key_guid       = key_guid;
                        cred.masterkey      = masterkey_decrypted.empty() ? masterkey_encrypted : masterkey_decrypted;
                        cred.sha1_masterkey = sha1_masterkey;
                        s.dpapi_credentials.push_back(cred);
                        break;
                    }
                }
            }

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(current, &next)) break;
            current = next;
        }
    };

    // Walk every candidate list that has a readable, non-empty sentinel.
    std::set<std::uint64_t> visited_sentinels;
    for (const std::uint64_t sp : all_candidates) {
        const std::uint64_t erl = sp + static_cast<std::int64_t>(feo);
        std::int32_t rel = 0;
        if (!vmem_.ReadStruct(erl, &rel)) continue;
        const std::uint64_t sentinel = erl + 4 + static_cast<std::int64_t>(rel);
        if (visited_sentinels.count(sentinel)) continue;
        visited_sentinels.insert(sentinel);
        std::uint64_t first = 0;
        if (!vmem_.ReadStruct(sentinel, &first)) continue;
        if (first == 0 || first == sentinel) continue;
        walk_one_list(sentinel, first);
    }
}

} // namespace KvcForensic::lsa
