#include "lsa/LogonSessionWalker.h"

#include "lsa/LsaReaderUtils.h"
#include "lsa/MsvWalker.h"
#include "lsa/WdigestWalker.h"
#include "lsa/KerberosWalker.h"
#include "lsa/DpapiWalker.h"

#include <algorithm>
#include <array>
#include <unordered_set>
#include <vector>

namespace KvcForensic::lsa {

namespace {

constexpr std::uint32_t kMinSessionCount = 2;
constexpr std::uint32_t kMaxSessionCount = 16;

} // namespace

// ---------------------------------------------------------------------------

LogonSessionWalker::LogonSessionWalker(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata)
    : vmem_(vmem)
    , metadata_(metadata)
    , secrets_extractor_(std::make_unique<security::LsaSecretsExtractor>(vmem, metadata)) {}

bool LogonSessionWalker::Initialize(std::uint32_t build_number) {
    if (secrets_extractor_)
        secrets_extractor_->Initialize(build_number);

    msv_template_      = templates::SelectMsvTemplateX64(build_number);
    wdigest_template_  = templates::SelectWdigestTemplateX64(build_number);
    kerberos_template_ = templates::SelectKerberosTemplateX64(build_number);
    dpapi_template_    = templates::SelectDpapiTemplateX64(build_number);

    if (msv_template_ == nullptr) return false;

    logon_list_va_ = FindMsvLogonList();
    if (logon_list_va_ == 0) return false;

    if (msv_template_->parser_support) {
        session_layout_.luid_offset            = msv_template_->session_luid_offset;
        session_layout_.username_offset        = msv_template_->session_username_offset;
        session_layout_.domain_offset          = msv_template_->session_domain_offset;
        session_layout_.sid_ptr_offset         = msv_template_->session_sid_ptr_offset;
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
        const std::uint64_t start = (std::max)(range.start_vva,
            static_cast<std::uint64_t>(lsasrv_mod->base_address));
        const std::uint64_t end = (std::min)(range.start_vva + range.size,
            static_cast<std::uint64_t>(lsasrv_mod->base_address + lsasrv_mod->size));

        if (start < end && (end - start) >= sig.size()) {
            std::vector<std::byte> chunk(end - start);
            if (vmem_.ReadBytes(start, chunk.size(), chunk)) {
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

    const std::uint64_t ptr_to_rel_offset =
        pos + static_cast<std::int64_t>(msv_template_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(ptr_to_rel_offset, &rel_offset)) return 0;

    std::uint64_t ptr_entry_loc = ptr_to_rel_offset + 4 + rel_offset;

    if (msv_template_->first_entry_offset_correction > 0) {
        std::uint32_t additional_offset = 0;
        const auto corr_loc = pos + static_cast<std::int64_t>(msv_template_->first_entry_offset_correction);
        if (vmem_.ReadStruct(corr_loc, &additional_offset))
            ptr_entry_loc += additional_offset;
    }

    ptr_entry_loc_ = ptr_entry_loc;

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

    if (session_count_ < kMinSessionCount) session_count_ = kMinSessionCount;
    if (session_count_ > kMaxSessionCount) session_count_ = kMaxSessionCount;

    std::uint64_t target_list = 0;
    if (!vmem_.ReadStruct(ptr_entry_loc, &target_list)) return 0;
    return target_list;
}

LogonSessionWalker::SessionFieldLayout LogonSessionWalker::DetectSessionFieldLayout() {
    struct Candidate { SessionFieldLayout layout; };
    const std::array<Candidate, 6> candidates{{
        { {0x70, 0xA0, 0xB0, 0xE0, 0x118} },
        { {0x68, 0x98, 0xA8, 0xD8, 0x110} },
        { {0x60, 0x90, 0xA0, 0xD0, 0x108} },
        { {0x58, 0x88, 0x98, 0xC8, 0x100} },
        { {0x50, 0x80, 0x90, 0xC0, 0xF8 } },
        { {0x48, 0x78, 0x88, 0xB8, 0xF0 } },
    }};

    auto score_candidate = [&](const SessionFieldLayout& f) -> int {
        int score = 0, samples = 0;

        for (std::uint32_t i = 0; i < session_count_ && i < 4; ++i) {
            const std::uint64_t skip_ptr =
                ptr_entry_loc_ + static_cast<std::uint64_t>(i) * 16;
            std::uint64_t list_head = 0;
            if (!vmem_.ReadStruct(skip_ptr, &list_head) || list_head == 0) continue;

            std::unordered_set<std::uint64_t> visited;
            std::uint64_t current = list_head;
            for (int n = 0; n < 8; ++n) {
                if (current == 0 || visited.count(current)) break;
                visited.insert(current);
                samples++;

                std::uint64_t luid = 0;
                if (vmem_.ReadStruct(current + f.luid_offset, &luid) && luid != 0) score += 3;

                const std::wstring user = ReadUnicodeString(vmem_, current + f.username_offset);
                const std::wstring dom  = ReadUnicodeString(vmem_, current + f.domain_offset);
                if (!user.empty() || !dom.empty()) score += 2;

                std::uint64_t sid_ptr = 0;
                if (vmem_.ReadStruct(current + f.sid_ptr_offset, &sid_ptr) && sid_ptr != 0) {
                    if (ReadSid(vmem_, sid_ptr).rfind("S-1-", 0) == 0) score += 2;
                }

                std::uint64_t creds_ptr = 0;
                if (vmem_.ReadStruct(current + f.credentials_ptr_offset, &creds_ptr)) score += 1;

                std::uint64_t next = 0;
                if (!vmem_.ReadStruct(current, &next) || next == list_head) break;
                current = next;
            }
        }

        return (samples == 0) ? -1 : score;
    };

    SessionFieldLayout best{};
    int best_score = -1;
    for (const auto& c : candidates) {
        const int sc = score_candidate(c.layout);
        if (sc > best_score) { best_score = sc; best = c.layout; }
    }
    if (best.luid_offset == 0) best = {0x70, 0xA0, 0xB0, 0xE0, 0x118};
    return best;
}

// ---------------------------------------------------------------------------

std::vector<LogonSession> LogonSessionWalker::Walk() {
    std::vector<LogonSession> sessions;
    if (logon_list_va_ == 0 || ptr_entry_loc_ == 0) return sessions;

    // --- 1. Enumerate logon sessions from the MSV list -----------------------
    for (std::uint32_t i = 0; i < session_count_; ++i) {
        const std::uint64_t skip_ptr =
            ptr_entry_loc_ + static_cast<std::uint64_t>(i) * 16;

        std::uint64_t list_head = 0;
        if (!vmem_.ReadStruct(skip_ptr, &list_head) || list_head == 0) continue;

        std::uint64_t current = 0;
        if (!vmem_.ReadStruct(list_head, &current)) continue;
        if (current == list_head) continue; // empty list

        std::unordered_set<std::uint64_t> visited;
        std::uint64_t walk_start = list_head;

        do {
            if (walk_start == 0) break;
            if (!visited.insert(walk_start).second) break;

            LogonSession session;
            session.address = walk_start;

            std::uint64_t luid = 0;
            if (vmem_.ReadStruct(walk_start + session_layout_.luid_offset, &luid))
                session.authentication_id = luid;

            session.username   = ReadUnicodeString(vmem_, walk_start + session_layout_.username_offset);
            session.domainname = ReadUnicodeString(vmem_, walk_start + session_layout_.domain_offset);

            std::uint64_t psid_ptr = 0;
            if (vmem_.ReadStruct(walk_start + session_layout_.sid_ptr_offset, &psid_ptr) && psid_ptr != 0)
                session.sid = ReadSid(vmem_, psid_ptr);

            std::uint64_t creds_ptr = 0;
            if (vmem_.ReadStruct(walk_start + session_layout_.credentials_ptr_offset, &creds_ptr))
                session.credentials_list_ptr = creds_ptr;

            if (session.authentication_id != 0)
                sessions.push_back(session);

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(walk_start, &next)) break;
            walk_start = next;
        } while (walk_start != 0 && walk_start != list_head);
    }

    // --- 2. Per-package credential extraction --------------------------------
    security::LsaSecretsExtractor* extractor = secrets_extractor_.get();

    MsvWalker msv(vmem_, extractor, msv_template_,
                  session_layout_.credentials_ptr_offset);
    for (auto& s : sessions) {
        msv.ExtractCredentials(s);
        msv.ExtractCredmanCredentials(s);
    }

    WdigestWalker(vmem_, metadata_, extractor, wdigest_template_).Walk(sessions);
    KerberosWalker(vmem_, metadata_, extractor, kerberos_template_).Walk(sessions);
    DpapiWalker(vmem_, metadata_, extractor, dpapi_template_).Walk(sessions);

    return sessions;
}

} // namespace KvcForensic::lsa
