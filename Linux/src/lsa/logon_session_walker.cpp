#include "lsa/logon_session_walker.h"

#include "core/signature_scanner.h"
#include "lsa/dpapi_walker.h"
#include "lsa/kerberos_walker.h"
#include "lsa/msv_walker.h"
#include "lsa/tspkg_walker.h"
#include "lsa/wdigest_walker.h"

#include <unordered_set>

namespace kvc::lsa {

namespace {

constexpr std::uint32_t kMinSessionCount = 2;
constexpr std::uint32_t kMaxSessionCount = 16;
constexpr std::uint32_t kMaxWalkNodesPerList = 4096;
constexpr std::uint32_t kMaxSessionsOverall = 8192;

} // namespace

LogonSessionWalker::LogonSessionWalker(const core::VirtualMemory& vmem,
                                       const minidump::DumpMetadata& metadata,
                                       const core::ModuleIndex& modules,
                                       const templates::TemplateRegistry& registry)
    : vmem_(vmem), metadata_(metadata), modules_(modules), registry_(registry),
      secrets_(std::make_unique<security::LsaSecretsExtractor>(vmem, metadata, modules, registry)) {}

bool LogonSessionWalker::is_readable_ptr(std::uint64_t va, std::size_t size) const {
    return vmem_.va_to_rva(va, size).has_value();
}

bool LogonSessionWalker::is_likely_luid(std::uint64_t luid) {
    if (luid == 0) return false;
    const auto high = static_cast<std::uint32_t>(luid >> 32);
    if (high == 0) return true;
    if (high == 0xFFFFFFFFu) return false;
    return high <= 0x0000FFFFu;
}

int LogonSessionWalker::score_layout(const SessionFieldLayout& layout,
                                     std::uint64_t ptr_entry_loc,
                                     std::uint32_t session_count) const {
    int score = 0;
    int samples = 0;
    for (std::uint32_t i = 0; i < session_count && i < 4; ++i) {
        const std::uint64_t skip_ptr = ptr_entry_loc + static_cast<std::uint64_t>(i) * 16;
        auto current_opt = vmem_.read_u64(skip_ptr);
        if (!current_opt || *current_opt == 0 || !is_readable_ptr(*current_opt, 16)) continue;
        std::uint64_t current = *current_opt;

        std::unordered_set<std::uint64_t> visited{skip_ptr};
        for (std::uint32_t n = 0; n < 8; ++n) {
            if (current == 0 || !visited.insert(current).second || !is_readable_ptr(current, 16)) break;
            ++samples;

            auto luid = vmem_.read_u64(current + layout.luid_offset);
            if (luid && is_likely_luid(*luid)) score += 3;

            const std::string user = vmem_.read_unicode_string(current + layout.username_offset);
            const std::string dom = vmem_.read_unicode_string(current + layout.domain_offset);
            if (!user.empty() || !dom.empty()) score += 2;

            auto sid_ptr = vmem_.read_u64(current + layout.sid_ptr_offset);
            if (sid_ptr && *sid_ptr != 0 && is_readable_ptr(*sid_ptr, 8)) {
                const auto sid = vmem_.read_sid(*sid_ptr);
                if (sid.rfind("S-1-", 0) == 0) score += 2;
            }

            auto creds_ptr = vmem_.read_u64(current + layout.credentials_ptr_offset);
            if (creds_ptr && (*creds_ptr == 0 || is_readable_ptr(*creds_ptr, 16))) score += 1;

            auto next = vmem_.read_u64(current);
            if (!next || *next == skip_ptr) break;
            current = *next;
        }
    }
    return samples == 0 ? -1 : score;
}

std::uint64_t LogonSessionWalker::find_msv_logon_list() {
    if (!msv_template_ || msv_template_->signature.empty()) return 0;
    session_count_ = 1;
    ptr_entry_loc_ = 0;

    const auto* lsasrv = modules_.find("lsasrv.dll");
    if (!lsasrv) return 0;

    const std::uint64_t pos = core::scan_module_first(
        vmem_, *lsasrv,
        std::span<const std::uint8_t>(msv_template_->signature.data(),
                                       msv_template_->signature.size()));
    if (pos == 0) return 0;

    const std::uint64_t ptr_to_rel = pos + static_cast<std::int64_t>(msv_template_->first_entry_offset);
    std::int32_t rel = 0;
    if (!vmem_.read_struct(ptr_to_rel, &rel)) return 0;
    std::uint64_t ptr_entry_loc = ptr_to_rel + 4 + static_cast<std::int64_t>(rel);

    if (msv_template_->first_entry_offset_correction > 0) {
        std::uint32_t additional = 0;
        const auto corr_loc = pos + static_cast<std::int64_t>(msv_template_->first_entry_offset_correction);
        if (vmem_.read_struct(corr_loc, &additional)) {
            ptr_entry_loc += additional;
        }
    }
    ptr_entry_loc_ = ptr_entry_loc;

    if (msv_template_->offset2 != 0) {
        const std::uint64_t count_ptr_loc = pos + static_cast<std::int64_t>(msv_template_->offset2);
        std::int32_t count_rel = 0;
        if (vmem_.read_struct(count_ptr_loc, &count_rel)) {
            const std::uint64_t count_loc = count_ptr_loc + 4 + static_cast<std::int64_t>(count_rel);
            std::uint8_t count = 0;
            if (vmem_.read_struct(count_loc, &count)) {
                session_count_ = count;
                if (session_count_ == 0) session_count_ = 1;
            }
        }
    }

    if (session_count_ < kMinSessionCount) session_count_ = kMinSessionCount;
    if (session_count_ > kMaxSessionCount) session_count_ = kMaxSessionCount;

    auto target = vmem_.read_u64(ptr_entry_loc);
    if (!target || *target == 0) return 0;
    return *target;
}

LogonSessionWalker::SessionFieldLayout LogonSessionWalker::detect_layout() {
    std::vector<SessionFieldLayout> candidates = {
        {0x70, 0xA0, 0xB0, 0xE0, 0x118},
        {0x68, 0x98, 0xA8, 0xD8, 0x110},
        {0x60, 0x90, 0xA0, 0xD0, 0x108},
        {0x58, 0x88, 0x98, 0xC8, 0x100},
        {0x50, 0x80, 0x90, 0xC0, 0xF8},
        {0x48, 0x78, 0x88, 0xB8, 0xF0},
    };
    if (msv_template_ && msv_template_->parser_support) {
        candidates.push_back({
            msv_template_->session_luid_offset,
            msv_template_->session_username_offset,
            msv_template_->session_domain_offset,
            msv_template_->session_sid_ptr_offset,
            msv_template_->session_credentials_ptr_offset,
        });
        if (msv_template_->session_sid_ptr_offset >= 8 &&
            msv_template_->session_credentials_ptr_offset >= 8) {
            candidates.push_back({
                msv_template_->session_luid_offset,
                msv_template_->session_username_offset,
                msv_template_->session_domain_offset,
                msv_template_->session_sid_ptr_offset - 8,
                msv_template_->session_credentials_ptr_offset - 8,
            });
        }
    }
    SessionFieldLayout best{};
    int best_score = -1;
    for (const auto& c : candidates) {
        const int sc = score_layout(c, ptr_entry_loc_, session_count_);
        if (sc > best_score) { best_score = sc; best = c; }
    }
    if (best.luid_offset == 0) best = {0x70, 0xA0, 0xB0, 0xE0, 0x118};
    return best;
}

bool LogonSessionWalker::configure_best_msv_template() {
    struct Cand {
        const templates::MsvTemplateSpec* spec = nullptr;
        std::uint64_t logon = 0;
        std::uint64_t ptr_entry = 0;
        std::uint32_t session_count = 0;
        SessionFieldLayout layout{};
        int score = -1;
    } best{};

    for (const auto* c : msv_candidates_) {
        if (!c) continue;
        msv_template_ = c;
        const std::uint64_t logon = find_msv_logon_list();
        if (logon == 0 || ptr_entry_loc_ == 0) continue;

        // Use template offsets when parser_support=true OR when the template
        // ships a complete non-zero set (e.g. 1803/1809 has all offsets but
        // is not flagged "parser_support" for historical reasons). Fall back
        // to the heuristic only when no usable offsets exist.
        const bool template_has_offsets =
            c->session_luid_offset != 0 &&
            c->session_username_offset != 0 &&
            c->session_domain_offset != 0 &&
            c->session_sid_ptr_offset != 0 &&
            c->session_credentials_ptr_offset != 0;
        const bool use_template_layout = c->parser_support || template_has_offsets;

        SessionFieldLayout layout{};
        if (use_template_layout) {
            layout.luid_offset = c->session_luid_offset;
            layout.username_offset = c->session_username_offset;
            layout.domain_offset = c->session_domain_offset;
            layout.sid_ptr_offset = c->session_sid_ptr_offset;
            layout.credentials_ptr_offset = c->session_credentials_ptr_offset;
            if (!c->parser_support) used_heuristic_ = true; // not validated upstream
        } else {
            layout = detect_layout();
            used_heuristic_ = true;
        }
        int score = score_layout(layout, ptr_entry_loc_, session_count_);

        // Compare template layout against heuristic and keep the higher score.
        // Helps when shipped offsets are stale (e.g. minor build drift inside
        // a template range).
        if (use_template_layout) {
            const auto heur = detect_layout();
            const int heur_score = score_layout(heur, ptr_entry_loc_, session_count_);
            if (heur_score > score) {
                layout = heur;
                score = heur_score;
                used_heuristic_ = true;
            }
        }

        if (use_template_layout) {
            SessionFieldLayout shifted = layout;
            if (shifted.sid_ptr_offset >= 8 && shifted.credentials_ptr_offset >= 8) {
                shifted.sid_ptr_offset -= 8;
                shifted.credentials_ptr_offset -= 8;
                const int sc = score_layout(shifted, ptr_entry_loc_, session_count_);
                if (sc > score) {
                    score = sc;
                    layout = shifted;
                    used_heuristic_ = true;
                }
            }
        }

        if (!best.spec || score > best.score) {
            best = {c, logon, ptr_entry_loc_, session_count_, layout, score};
        }
    }
    if (!best.spec) return false;

    msv_template_ = best.spec;
    active_msv_template_ = *best.spec;
    logon_list_va_ = best.logon;
    ptr_entry_loc_ = best.ptr_entry;
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
            used_heuristic_ = true;
        }
        if (best.spec->session_credentials_ptr_offset > 0 &&
            best.spec->session_credman_ptr_offset > 0) {
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

bool LogonSessionWalker::initialize(std::uint32_t build_number) {
    used_heuristic_ = false;
    used_runtime_fallback_ = false;
    last_error_.clear();

    if (secrets_) {
        if (!secrets_->initialize(build_number)) {
            last_error_ = "secrets init: " + secrets_->last_error();
        }
    }

    msv_candidates_ = registry_.select_msv_candidates(build_number);
    if (msv_candidates_.empty()) {
        if (const auto* single = registry_.select_msv(build_number)) {
            msv_candidates_.push_back(single);
        }
    }
    msv_template_ = msv_candidates_.empty() ? nullptr : msv_candidates_.front();
    wdigest_template_ = registry_.select_wdigest(build_number);
    kerberos_template_ = registry_.select_kerberos(build_number);
    dpapi_template_ = registry_.select_dpapi(build_number);
    tspkg_template_ = registry_.select_tspkg(build_number);

    if (!msv_template_) { last_error_ = "no msv template"; return false; }
    if (!configure_best_msv_template()) { last_error_ = "msv template selection failed"; return false; }
    if (logon_list_va_ == 0) { last_error_ = "logon_list_va_ == 0"; return false; }
    if (session_layout_.luid_offset == 0 || session_layout_.credentials_ptr_offset == 0) {
        last_error_ = "session layout invalid"; return false;
    }
    return true;
}

std::vector<LogonSession> LogonSessionWalker::enumerate(const SessionFieldLayout& layout) const {
    std::vector<LogonSession> sessions;
    if (logon_list_va_ == 0 || ptr_entry_loc_ == 0) return sessions;

    for (std::uint32_t i = 0; i < session_count_ && sessions.size() < kMaxSessionsOverall; ++i) {
        const std::uint64_t skip_ptr = ptr_entry_loc_ + static_cast<std::uint64_t>(i) * 16;
        auto current_opt = vmem_.read_u64(skip_ptr);
        if (!current_opt || *current_opt == 0 || !is_readable_ptr(*current_opt, 16)) continue;
        if (*current_opt == skip_ptr) continue;
        std::uint64_t current = *current_opt;

        std::unordered_set<std::uint64_t> visited{skip_ptr};
        std::uint32_t safety = 0;
        do {
            if (current == 0 || !is_readable_ptr(current, 16)) break;
            if (!visited.insert(current).second) break;
            if (++safety > kMaxWalkNodesPerList) break;

            LogonSession s;
            s.address = current;

            auto luid = vmem_.read_u64(current + layout.luid_offset);
            if (luid && is_likely_luid(*luid)) s.authentication_id = *luid;

            s.username = vmem_.read_unicode_string(current + layout.username_offset);
            s.domainname = vmem_.read_unicode_string(current + layout.domain_offset);

            auto sid_ptr = vmem_.read_u64(current + layout.sid_ptr_offset);
            if (sid_ptr && *sid_ptr != 0 && is_readable_ptr(*sid_ptr, 8)) {
                s.sid = vmem_.read_sid(*sid_ptr);
            }

            auto creds_ptr = vmem_.read_u64(current + layout.credentials_ptr_offset);
            if (creds_ptr && (*creds_ptr == 0 || is_readable_ptr(*creds_ptr, 16))) {
                s.credentials_list_ptr = *creds_ptr;
            }

            if (s.authentication_id != 0) sessions.push_back(std::move(s));

            auto next = vmem_.read_u64(current);
            if (!next) break;
            current = *next;
        } while (current != 0 && current != skip_ptr && sessions.size() < kMaxSessionsOverall);
    }
    return sessions;
}

std::vector<LogonSession> LogonSessionWalker::walk() {
    if (logon_list_va_ == 0 || ptr_entry_loc_ == 0) return {};

    std::vector<LogonSession> sessions = enumerate(session_layout_);

    std::size_t sid_like = 0;
    for (const auto& s : sessions) {
        if (!s.sid.empty() && s.sid.rfind("S-1-", 0) == 0) ++sid_like;
    }
    if (sessions.empty() || (sid_like == 0 && msv_template_ && msv_template_->parser_support)) {
        const auto detected = detect_layout();
        const int cur = score_layout(session_layout_, ptr_entry_loc_, session_count_);
        const int alt = score_layout(detected, ptr_entry_loc_, session_count_);
        if (alt > cur) {
            used_runtime_fallback_ = true;
            used_heuristic_ = true;
            session_layout_ = detected;
            active_msv_template_.session_luid_offset = detected.luid_offset;
            active_msv_template_.session_username_offset = detected.username_offset;
            active_msv_template_.session_domain_offset = detected.domain_offset;
            active_msv_template_.session_sid_ptr_offset = detected.sid_ptr_offset;
            active_msv_template_.session_credentials_ptr_offset = detected.credentials_ptr_offset;
            sessions = enumerate(session_layout_);
        }
    }

    MsvWalker msv(vmem_, secrets_.get(), &active_msv_template_,
                  session_layout_.credentials_ptr_offset);
    for (auto& s : sessions) {
        msv.extract(s);
        msv.extract_credman(s);
    }

    WdigestWalker(vmem_, modules_, secrets_.get(), wdigest_template_).walk(sessions);
    TspkgWalker(vmem_, modules_, secrets_.get(), tspkg_template_).walk(sessions);
    KerberosWalker(vmem_, modules_, secrets_.get(), kerberos_template_).walk(sessions);
    DpapiWalker(vmem_, modules_, secrets_.get(), dpapi_template_).walk(sessions);
    return sessions;
}

} // namespace kvc::lsa
