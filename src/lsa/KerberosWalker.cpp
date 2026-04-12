#include "lsa/KerberosWalker.h"

#include "lsa/LsaReaderUtils.h"

#include <set>
#include <vector>

namespace KvcForensic::lsa {

KerberosWalker::KerberosWalker(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    security::LsaSecretsExtractor* extractor,
    const templates::KerberosTemplateSpec* tmpl)
    : vmem_(vmem), metadata_(metadata), extractor_(extractor), tmpl_(tmpl) {}

void KerberosWalker::Walk(std::vector<LogonSession>& sessions) {
    if (tmpl_ == nullptr || tmpl_->signature.empty()) return;

    const std::uint64_t sig_pos = FindSignatureInModule(
        vmem_, metadata_, L"kerberos.dll", tmpl_->signature);
    if (sig_pos == 0) return;

    const std::uint64_t entry_ref_loc =
        sig_pos + static_cast<std::int64_t>(tmpl_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(entry_ref_loc, &rel_offset)) return;
    const std::uint64_t avl_table_loc =
        entry_ref_loc + 4 + static_cast<std::int64_t>(rel_offset);

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

void KerberosWalker::WalkAvlNode(
    const std::uint64_t node_addr,
    const std::uint64_t table_addr,
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

        // RTL_BALANCED_LINKS (32 bytes): Parent(8)+LeftChild(8)+RightChild(8)+...
        // OrderedPointer (session ptr) at node+32
        std::uint64_t session_ptr = 0;
        vmem_.ReadStruct(current + 32, &session_ptr);

        if (session_ptr != 0) {
            auto luid_exists = [&](const std::uint64_t luid) -> bool {
                if (luid == 0) return false;
                for (const auto& s : sessions)
                    if (s.authentication_id == luid) return true;
                return false;
            };

            std::uint64_t entry_luid = 0;
            vmem_.ReadStruct(session_ptr + tmpl_->session_luid_offset, &entry_luid);
            if (!luid_exists(entry_luid)) {
                for (const auto off : tmpl_->session_luid_fallback_offsets) {
                    std::uint64_t alt_luid = 0;
                    if (vmem_.ReadStruct(session_ptr + off, &alt_luid) && luid_exists(alt_luid)) {
                        entry_luid = alt_luid;
                        break;
                    }
                }
            }

            const std::wstring username   = ReadUnicodeString(vmem_, session_ptr + tmpl_->session_username_offset);
            const std::wstring domainname = ReadUnicodeString(vmem_, session_ptr + tmpl_->session_domain_offset);

            std::uint16_t pwd_len = 0, pwd_max_len = 0;
            std::uint64_t pwd_buffer = 0;
            const auto pwd_off = tmpl_->session_password_ustr_offset;
            vmem_.ReadStruct(session_ptr + pwd_off,     &pwd_len);
            vmem_.ReadStruct(session_ptr + pwd_off + 2, &pwd_max_len);
            vmem_.ReadStruct(session_ptr + pwd_off + 8, &pwd_buffer);

            std::wstring password;
            std::wstring password_hex;
            if (pwd_max_len > 0 && pwd_buffer != 0 &&
                extractor_ && extractor_->IsInitialized()) {
                std::vector<std::byte> enc_bytes(pwd_max_len);
                if (vmem_.ReadBytes(pwd_buffer, pwd_max_len, enc_bytes)) {
                    auto dec = extractor_->Decrypt(enc_bytes);
                    DecodePasswordCandidate(dec, pwd_len, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        security::KerberosCredential cred;
                        cred.luid         = entry_luid;
                        cred.username     = username;
                        cred.domainname   = domainname;
                        cred.password     = password;
                        cred.password_hex = password_hex;
                        WalkKerberosTickets(session_ptr, cred);
                        if (cred.username.empty() && (!cred.password.empty() || !cred.password_hex.empty() || !cred.tickets.empty())) {
                            cred.username = s.username;
                        }
                        if (cred.domainname.empty() && (!cred.password.empty() || !cred.password_hex.empty() || !cred.tickets.empty())) {
                            cred.domainname = s.domainname;
                        }
                        if (cred.username.empty() && cred.domainname.empty() &&
                            cred.password.empty() && cred.password_hex.empty() &&
                            cred.tickets.empty()) {
                            break;
                        }
                        s.kerberos_credentials.push_back(cred);
                        break;
                    }
                }
            }
        }

        // Push children (right first so left is processed first)
        std::uint64_t left_child = 0, right_child = 0;
        vmem_.ReadStruct(current + 8,  &left_child);
        vmem_.ReadStruct(current + 16, &right_child);
        if (right_child != 0 && right_child != table_addr && !visited.count(right_child))
            stack.push_back(right_child);
        if (left_child != 0 && left_child != table_addr && !visited.count(left_child))
            stack.push_back(left_child);
    }
}

void KerberosWalker::WalkKerberosTickets(
    const std::uint64_t session_ptr,
    security::KerberosCredential& cred) {

    if (tmpl_ == nullptr || tmpl_->ticket_list_offsets.empty()) return;

    for (const std::size_t ticket_offset : tmpl_->ticket_list_offsets) {
        std::uint64_t flink = 0;
        if (!vmem_.ReadStruct(session_ptr + ticket_offset, &flink)) continue;

        const std::uint64_t list_head = session_ptr + ticket_offset;
        if (flink == 0 || flink == list_head || flink == list_head - 4) continue;

        std::uint64_t current = flink;
        std::set<std::uint64_t> visited;

        while (current != 0 && current != list_head) {
            if (visited.count(current)) break;
            visited.insert(current);

            std::uint64_t service_name_ptr = 0, target_name_ptr = 0, client_name_ptr = 0;
            std::uint32_t ticket_flags = 0, key_type = 0, ticket_enc_type = 0;
            std::uint32_t ticket_kvno = 0, ticket_len = 0;
            std::uint64_t ticket_buffer = 0;

            vmem_.ReadStruct(current + tmpl_->ticket_service_name_offset, &service_name_ptr);
            vmem_.ReadStruct(current + tmpl_->ticket_target_name_offset,  &target_name_ptr);
            vmem_.ReadStruct(current + tmpl_->ticket_client_name_offset,  &client_name_ptr);
            vmem_.ReadStruct(current + tmpl_->ticket_flags_offset,        &ticket_flags);
            vmem_.ReadStruct(current + tmpl_->ticket_key_type_offset,     &key_type);
            vmem_.ReadStruct(current + tmpl_->ticket_enc_type_offset,     &ticket_enc_type);
            vmem_.ReadStruct(current + tmpl_->ticket_kvno_offset,         &ticket_kvno);
            vmem_.ReadStruct(current + tmpl_->ticket_buffer_len_offset,   &ticket_len);
            vmem_.ReadStruct(current + tmpl_->ticket_buffer_ptr_offset,   &ticket_buffer);

            const auto ext_off = tmpl_->external_name_first_string_offset;
            std::wstring service_name, target_name, client_name;
            if (service_name_ptr != 0) service_name = ReadUnicodeString(vmem_, service_name_ptr + ext_off);
            if (target_name_ptr  != 0) target_name  = ReadUnicodeString(vmem_, target_name_ptr  + ext_off);
            if (client_name_ptr  != 0) client_name  = ReadUnicodeString(vmem_, client_name_ptr  + ext_off);

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

} // namespace KvcForensic::lsa
