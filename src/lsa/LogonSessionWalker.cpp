#include "lsa/LogonSessionWalker.h"

#include "lsa/LsaReaderUtils.h"
#include "lsa/MsvWalker.h"
#include "lsa/WdigestWalker.h"
#include "lsa/KerberosWalker.h"
#include "lsa/DpapiWalker.h"
#include "lsa/TspkgWalker.h"

#include <algorithm>
#include <unordered_set>
#include <vector>

namespace KvcForensic::lsa {

namespace {

constexpr std::uint32_t kMinSessionCount = 2;
constexpr std::uint32_t kMaxSessionCount = 16;
constexpr std::uint32_t kMaxWalkNodesPerList = 4096;
constexpr std::uint32_t kMaxSessionsOverall = 8192;

} // namespace

// ---------------------------------------------------------------------------

LogonSessionWalker::LogonSessionWalker(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata)
    : vmem_(vmem)
    , metadata_(metadata)
    , secrets_extractor_(std::make_unique<security::LsaSecretsExtractor>(vmem, metadata)) {}

bool LogonSessionWalker::Initialize(std::uint32_t build_number) {
    used_heuristic_layout_ = false;
    used_runtime_fallback_ = false;

    if (secrets_extractor_)
        secrets_extractor_->Initialize(build_number);

    msv_template_candidates_ = templates::SelectMsvTemplateCandidatesX64(build_number);
    if (msv_template_candidates_.empty()) {
        // Backward-compatible fallback when only a single matching range exists.
        if (const auto* single = templates::SelectMsvTemplateX64(build_number); single != nullptr) {
            msv_template_candidates_.push_back(single);
        }
    }
    msv_template_      = msv_template_candidates_.empty() ? nullptr : msv_template_candidates_.front();
    wdigest_template_  = templates::SelectWdigestTemplateX64(build_number);
    kerberos_template_ = templates::SelectKerberosTemplateX64(build_number);
    dpapi_template_    = templates::SelectDpapiTemplateX64(build_number);
    tspkg_template_    = templates::SelectTspkgTemplateX64(build_number);

    if (msv_template_ == nullptr) return false;

    if (!ConfigureBestMsvTemplateAndLayout(build_number)) {
        return false;
    }

    if (logon_list_va_ == 0) return false;

    return session_layout_.luid_offset != 0 && session_layout_.credentials_ptr_offset != 0;
}

bool LogonSessionWalker::IsReadablePointer(const std::uint64_t va, const std::size_t size) const {
    return vmem_.VaToRva(va, size).has_value();
}

bool LogonSessionWalker::IsLikelyLuid(const std::uint64_t luid) {
    if (luid == 0) return false;
    const std::uint32_t high = static_cast<std::uint32_t>(luid >> 32);
    // Keep strict filtering (prefer classic low-32bit LUIDs), but allow
    // small non-zero HighPart values seen on some builds.
    if (high == 0) return true;
    if (high == 0xFFFFFFFFu) return false;
    return high <= 0x0000FFFFu;
}

int LogonSessionWalker::ScoreSessionFieldLayout(
    const SessionFieldLayout& layout,
    const std::uint64_t ptr_entry_loc,
    const std::uint32_t session_count) const {
    int score = 0;
    int samples = 0;

    for (std::uint32_t i = 0; i < session_count && i < 4; ++i) {
        const std::uint64_t skip_ptr = ptr_entry_loc + static_cast<std::uint64_t>(i) * 16;
        std::uint64_t list_head = 0;
        if (!vmem_.ReadStruct(skip_ptr, &list_head) || list_head == 0 || !IsReadablePointer(list_head, 16)) {
            continue;
        }

        std::unordered_set<std::uint64_t> visited;
        std::uint64_t current = list_head;
        for (std::uint32_t n = 0; n < 8; ++n) {
            if (current == 0 || !visited.insert(current).second || !IsReadablePointer(current, 16)) break;
            ++samples;

            std::uint64_t luid = 0;
            if (vmem_.ReadStruct(current + layout.luid_offset, &luid) && IsLikelyLuid(luid)) score += 3;

            const std::wstring user = ReadUnicodeString(vmem_, current + layout.username_offset);
            const std::wstring dom  = ReadUnicodeString(vmem_, current + layout.domain_offset);
            if (!user.empty() || !dom.empty()) score += 2;

            std::uint64_t sid_ptr = 0;
            if (vmem_.ReadStruct(current + layout.sid_ptr_offset, &sid_ptr) && sid_ptr != 0 && IsReadablePointer(sid_ptr, 8)) {
                if (ReadSid(vmem_, sid_ptr).rfind("S-1-", 0) == 0) score += 2;
            }

            std::uint64_t creds_ptr = 0;
            if (vmem_.ReadStruct(current + layout.credentials_ptr_offset, &creds_ptr) &&
                (creds_ptr == 0 || IsReadablePointer(creds_ptr, 16))) {
                score += 1;
            }

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(current, &next) || next == list_head) break;
            current = next;
        }
    }

    return (samples == 0) ? -1 : score;
}

bool LogonSessionWalker::ConfigureBestMsvTemplateAndLayout(const std::uint32_t /*build_number*/) {
    struct CandidateResult {
        const templates::MsvTemplateSpec* spec = nullptr;
        std::uint64_t logon_list = 0;
        std::uint64_t ptr_entry_loc = 0;
        std::uint32_t session_count = 0;
        SessionFieldLayout layout{};
        int score = -1;
    };

    CandidateResult best{};
    for (const auto* candidate : msv_template_candidates_) {
        if (candidate == nullptr) continue;

        msv_template_ = candidate;
        const std::uint64_t logon_list = FindMsvLogonList();
        if (logon_list == 0 || ptr_entry_loc_ == 0) {
            continue;
        }

        SessionFieldLayout template_layout{};
        if (candidate->parser_support) {
            template_layout.luid_offset = candidate->session_luid_offset;
            template_layout.username_offset = candidate->session_username_offset;
            template_layout.domain_offset = candidate->session_domain_offset;
            template_layout.sid_ptr_offset = candidate->session_sid_ptr_offset;
            template_layout.credentials_ptr_offset = candidate->session_credentials_ptr_offset;
        } else {
            template_layout = DetectSessionFieldLayout();
            used_heuristic_layout_ = true;
        }

        int score = ScoreSessionFieldLayout(template_layout, ptr_entry_loc_, session_count_);

        // Wider search window: if parser offsets are weak, probe one nearby shifted variant.
        if (candidate->parser_support) {
            SessionFieldLayout shifted = template_layout;
            if (shifted.sid_ptr_offset >= 8 && shifted.credentials_ptr_offset >= 8) {
                shifted.sid_ptr_offset -= 8;
                shifted.credentials_ptr_offset -= 8;
                const int shifted_score = ScoreSessionFieldLayout(shifted, ptr_entry_loc_, session_count_);
                if (shifted_score > score) {
                    score = shifted_score;
                    template_layout = shifted;
                    used_heuristic_layout_ = true;
                }
            }
        }

        if (best.spec == nullptr || score > best.score) {
            best.spec = candidate;
            best.logon_list = logon_list;
            best.ptr_entry_loc = ptr_entry_loc_;
            best.session_count = session_count_;
            best.layout = template_layout;
            best.score = score;
        }
    }

    if (best.spec == nullptr || best.logon_list == 0) {
        return false;
    }

    msv_template_ = best.spec;
    active_msv_template_ = *best.spec;
    logon_list_va_ = best.logon_list;
    ptr_entry_loc_ = best.ptr_entry_loc;
    session_count_ = best.session_count;
    session_layout_ = best.layout;

    if (best.spec->parser_support) {
        active_msv_template_.session_luid_offset = session_layout_.luid_offset;
        active_msv_template_.session_username_offset = session_layout_.username_offset;
        active_msv_template_.session_domain_offset = session_layout_.domain_offset;
        active_msv_template_.session_sid_ptr_offset = session_layout_.sid_ptr_offset;
        active_msv_template_.session_credentials_ptr_offset = session_layout_.credentials_ptr_offset;
        if (session_layout_.luid_offset != best.spec->session_luid_offset ||
            session_layout_.username_offset != best.spec->session_username_offset ||
            session_layout_.domain_offset != best.spec->session_domain_offset ||
            session_layout_.sid_ptr_offset != best.spec->session_sid_ptr_offset ||
            session_layout_.credentials_ptr_offset != best.spec->session_credentials_ptr_offset) {
            used_heuristic_layout_ = true;
        }

        if (best.spec->session_credentials_ptr_offset > 0 && best.spec->session_credman_ptr_offset > 0) {
            const auto delta = static_cast<std::ptrdiff_t>(session_layout_.credentials_ptr_offset) -
                               static_cast<std::ptrdiff_t>(best.spec->session_credentials_ptr_offset);
            const auto adjusted = static_cast<std::ptrdiff_t>(best.spec->session_credman_ptr_offset) + delta;
            if (adjusted > 0) {
                active_msv_template_.session_credman_ptr_offset = static_cast<std::size_t>(adjusted);
            }
        }
    }
    return true;
}

std::uint64_t LogonSessionWalker::FindMsvLogonList() {
    if (msv_template_ == nullptr || msv_template_->signature.empty()) return 0;
    session_count_ = 1;
    ptr_entry_loc_ = 0;

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

    if (!IsReadablePointer(ptr_entry_loc, 8)) return 0;
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
    if (target_list == 0 || !IsReadablePointer(target_list, 16)) return 0;
    return target_list;
}

LogonSessionWalker::SessionFieldLayout LogonSessionWalker::DetectSessionFieldLayout() {
    std::vector<SessionFieldLayout> candidates = {
        {0x70, 0xA0, 0xB0, 0xE0, 0x118},
        {0x68, 0x98, 0xA8, 0xD8, 0x110},
        {0x60, 0x90, 0xA0, 0xD0, 0x108},
        {0x58, 0x88, 0x98, 0xC8, 0x100},
        {0x50, 0x80, 0x90, 0xC0, 0xF8},
        {0x48, 0x78, 0x88, 0xB8, 0xF0}
    };
    if (msv_template_ != nullptr && msv_template_->parser_support) {
        candidates.push_back({
            msv_template_->session_luid_offset,
            msv_template_->session_username_offset,
            msv_template_->session_domain_offset,
            msv_template_->session_sid_ptr_offset,
            msv_template_->session_credentials_ptr_offset
        });
        if (msv_template_->session_sid_ptr_offset >= 8 && msv_template_->session_credentials_ptr_offset >= 8) {
            candidates.push_back({
                msv_template_->session_luid_offset,
                msv_template_->session_username_offset,
                msv_template_->session_domain_offset,
                msv_template_->session_sid_ptr_offset - 8,
                msv_template_->session_credentials_ptr_offset - 8
            });
        }
    }

    SessionFieldLayout best{};
    int best_score = -1;
    for (const auto& c : candidates) {
        const int sc = ScoreSessionFieldLayout(c, ptr_entry_loc_, session_count_);
        if (sc > best_score) { best_score = sc; best = c; }
    }
    if (best.luid_offset == 0) best = {0x70, 0xA0, 0xB0, 0xE0, 0x118};
    return best;
}

// ---------------------------------------------------------------------------

std::vector<LogonSession> LogonSessionWalker::EnumerateSessionsWithLayout(const SessionFieldLayout& layout) const {
    std::vector<LogonSession> sessions;
    if (logon_list_va_ == 0 || ptr_entry_loc_ == 0) return sessions;

    for (std::uint32_t i = 0; i < session_count_ && sessions.size() < kMaxSessionsOverall; ++i) {
        const std::uint64_t skip_ptr = ptr_entry_loc_ + static_cast<std::uint64_t>(i) * 16;

        std::uint64_t list_head = 0;
        if (!vmem_.ReadStruct(skip_ptr, &list_head) || list_head == 0 || !IsReadablePointer(list_head, 16)) continue;

        std::uint64_t current = 0;
        if (!vmem_.ReadStruct(list_head, &current) || !IsReadablePointer(current, 16)) continue;
        if (current == list_head) continue;

        std::unordered_set<std::uint64_t> visited;
        std::uint64_t walk_start = list_head;
        std::uint32_t safety = 0;

        do {
            if (walk_start == 0 || !IsReadablePointer(walk_start, 16)) break;
            if (!visited.insert(walk_start).second) break;
            if (++safety > kMaxWalkNodesPerList) break;

            LogonSession session;
            session.address = walk_start;

            std::uint64_t luid = 0;
            if (vmem_.ReadStruct(walk_start + layout.luid_offset, &luid) && IsLikelyLuid(luid))
                session.authentication_id = luid;

            session.username   = ReadUnicodeString(vmem_, walk_start + layout.username_offset);
            session.domainname = ReadUnicodeString(vmem_, walk_start + layout.domain_offset);

            std::uint64_t psid_ptr = 0;
            if (vmem_.ReadStruct(walk_start + layout.sid_ptr_offset, &psid_ptr) && psid_ptr != 0 && IsReadablePointer(psid_ptr, 8))
                session.sid = ReadSid(vmem_, psid_ptr);

            std::uint64_t creds_ptr = 0;
            if (vmem_.ReadStruct(walk_start + layout.credentials_ptr_offset, &creds_ptr) &&
                (creds_ptr == 0 || IsReadablePointer(creds_ptr, 16))) {
                session.credentials_list_ptr = creds_ptr;
            }

            if (session.authentication_id != 0)
                sessions.push_back(std::move(session));

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(walk_start, &next)) break;
            walk_start = next;
        } while (walk_start != 0 && walk_start != list_head && sessions.size() < kMaxSessionsOverall);
    }
    return sessions;
}

std::vector<LogonSession> LogonSessionWalker::Walk() {
    if (logon_list_va_ == 0 || ptr_entry_loc_ == 0) return {};

    std::vector<LogonSession> sessions = EnumerateSessionsWithLayout(session_layout_);

    // Last-chance runtime fallback even when parser_support=true:
    // if parsed sessions look implausible, rerun with heuristic layout.
    std::size_t sid_like = 0;
    for (const auto& s : sessions) {
        if (!s.sid.empty() && s.sid.rfind("S-1-", 0) == 0) {
            ++sid_like;
        }
    }
    if (sessions.empty() || (sid_like == 0 && msv_template_ != nullptr && msv_template_->parser_support)) {
        const auto detected = DetectSessionFieldLayout();
        const int cur_score = ScoreSessionFieldLayout(session_layout_, ptr_entry_loc_, session_count_);
        const int det_score = ScoreSessionFieldLayout(detected, ptr_entry_loc_, session_count_);
        if (det_score > cur_score) {
            used_runtime_fallback_ = true;
            used_heuristic_layout_ = true;
            session_layout_ = detected;
            active_msv_template_.session_luid_offset = detected.luid_offset;
            active_msv_template_.session_username_offset = detected.username_offset;
            active_msv_template_.session_domain_offset = detected.domain_offset;
            active_msv_template_.session_sid_ptr_offset = detected.sid_ptr_offset;
            active_msv_template_.session_credentials_ptr_offset = detected.credentials_ptr_offset;
            sessions = EnumerateSessionsWithLayout(session_layout_);
        }
    }

    // --- 2. Per-package credential extraction --------------------------------
    security::LsaSecretsExtractor* extractor = secrets_extractor_.get();

    MsvWalker msv(vmem_, extractor, &active_msv_template_,
                  session_layout_.credentials_ptr_offset);
    for (auto& s : sessions) {
        msv.ExtractCredentials(s);
        msv.ExtractCredmanCredentials(s);
    }

    WdigestWalker(vmem_, metadata_, extractor, wdigest_template_).Walk(sessions);
    TspkgWalker(vmem_, metadata_, extractor, tspkg_template_).Walk(sessions);
    KerberosWalker(vmem_, metadata_, extractor, kerberos_template_).Walk(sessions);
    DpapiWalker(vmem_, metadata_, extractor, dpapi_template_).Walk(sessions);

    return sessions;
}

} // namespace KvcForensic::lsa
