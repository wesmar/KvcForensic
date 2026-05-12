#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace kvc::lsa::templates {

struct MsvTemplateSpec {
    std::string name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    int offset2 = 0;
    int first_entry_offset_correction = 0;

    std::size_t session_luid_offset = 0;
    std::size_t session_username_offset = 0;
    std::size_t session_domain_offset = 0;
    std::size_t session_sid_ptr_offset = 0;
    std::size_t session_credentials_ptr_offset = 0;
    std::size_t session_credman_ptr_offset = 0;
    bool parser_support = false;
};

struct WdigestTemplateSpec {
    std::string name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    std::size_t primary_offset = 0;
};

struct KerberosTemplateSpec {
    std::string name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;

    std::size_t session_luid_offset = 0;
    std::size_t session_username_offset = 0;
    std::size_t session_domain_offset = 0;
    std::size_t session_password_ustr_offset = 0;
    std::vector<std::size_t> session_luid_fallback_offsets;

    std::vector<std::size_t> ticket_list_offsets;

    std::size_t ticket_service_name_offset = 0;
    std::size_t ticket_target_name_offset = 0;
    std::size_t ticket_client_name_offset = 0;
    std::size_t ticket_flags_offset = 0;
    std::size_t ticket_key_type_offset = 0;
    std::size_t ticket_enc_type_offset = 0;
    std::size_t ticket_kvno_offset = 0;
    std::size_t ticket_buffer_len_offset = 0;
    std::size_t ticket_buffer_ptr_offset = 0;
    std::size_t external_name_first_string_offset = 0;
};

struct DpapiTemplateSpec {
    std::string name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
};

struct TspkgTemplateSpec {
    std::string name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    std::size_t luid_offset = 16;
    std::size_t primary_offset = 24;
    std::size_t blob_header_skip = 0;
};

struct LsaSecretsTemplateSpec {
    std::string name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int offset_to_iv_ptr = 0;
    int offset_to_aes_key_ptr = 0;
    int offset_to_des_key_ptr = 0;
    std::size_t iv_length = 16;

    std::size_t handle_ptr_key_offset = 16;
    std::size_t key_cb_secret_offset = 56;
    std::size_t key_data_offset = 60;
};

class TemplateRegistry {
public:
    bool load(const std::filesystem::path& json_path);
    const std::string& last_error() const { return error_; }

    const MsvTemplateSpec* select_msv(std::uint32_t build) const;
    std::vector<const MsvTemplateSpec*> select_msv_candidates(std::uint32_t build) const;
    const WdigestTemplateSpec* select_wdigest(std::uint32_t build) const;
    const KerberosTemplateSpec* select_kerberos(std::uint32_t build) const;
    const DpapiTemplateSpec* select_dpapi(std::uint32_t build) const;
    const LsaSecretsTemplateSpec* select_lsa_secrets(std::uint32_t build) const;
    std::vector<const LsaSecretsTemplateSpec*> select_lsa_secrets_candidates(std::uint32_t build) const;
    const TspkgTemplateSpec* select_tspkg(std::uint32_t build) const;

    const std::vector<MsvTemplateSpec>& msv_all() const { return msv_; }
    const std::vector<WdigestTemplateSpec>& wdigest_all() const { return wdigest_; }
    const std::vector<KerberosTemplateSpec>& kerberos_all() const { return kerberos_; }
    const std::vector<DpapiTemplateSpec>& dpapi_all() const { return dpapi_; }
    const std::vector<LsaSecretsTemplateSpec>& lsa_secrets_all() const { return lsa_secrets_; }
    const std::vector<TspkgTemplateSpec>& tspkg_all() const { return tspkg_; }

    std::size_t total_count() const {
        return msv_.size() + wdigest_.size() + kerberos_.size() +
               dpapi_.size() + lsa_secrets_.size() + tspkg_.size();
    }

private:
    std::vector<MsvTemplateSpec> msv_;
    std::vector<WdigestTemplateSpec> wdigest_;
    std::vector<KerberosTemplateSpec> kerberos_;
    std::vector<DpapiTemplateSpec> dpapi_;
    std::vector<LsaSecretsTemplateSpec> lsa_secrets_;
    std::vector<TspkgTemplateSpec> tspkg_;
    std::string error_;
};

} // namespace kvc::lsa::templates
