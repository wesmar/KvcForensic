#pragma once

#include "core/module_index.h"
#include "core/virtual_memory.h"
#include "lsa/template_registry.h"
#include "minidump/minidump_parser.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kvc::security {

// Locates the AES key, 3DES key and IV that LSA uses to encrypt session
// credentials. Once initialised, Decrypt() consumes encrypted ciphertexts
// straight out of the dump and returns plaintexts.
class LsaSecretsExtractor {
public:
    LsaSecretsExtractor(const core::VirtualMemory& vmem,
                        const minidump::DumpMetadata& metadata,
                        const core::ModuleIndex& modules,
                        const lsa::templates::TemplateRegistry& registry);

    bool initialize(std::uint32_t build_number);
    bool is_initialized() const { return initialized_; }

    const std::vector<std::byte>& aes_key() const { return aes_key_; }
    const std::vector<std::byte>& des_key() const { return des_key_; }
    const std::vector<std::byte>& iv() const { return iv_; }

    const std::string& last_error() const { return last_error_; }
    std::uint64_t signature_va() const { return signature_va_; }
    const std::string& active_template_name() const { return active_template_name_; }

    // Decrypts using AES-CFB128 when size%8 != 0, otherwise 3DES-CBC.
    std::vector<std::byte> decrypt(std::span<const std::byte> encrypted) const;

private:
    std::uint64_t get_ptr_with_offset(std::uint64_t pos) const;
    bool extract_iv(std::uint64_t sig_pos, const lsa::templates::LsaSecretsTemplateSpec& spec);
    bool extract_aes_key(std::uint64_t sig_pos, const lsa::templates::LsaSecretsTemplateSpec& spec);
    bool extract_des_key(std::uint64_t sig_pos, const lsa::templates::LsaSecretsTemplateSpec& spec);

    const core::VirtualMemory& vmem_;
    const minidump::DumpMetadata& metadata_;
    const core::ModuleIndex& modules_;
    const lsa::templates::TemplateRegistry& registry_;

    std::vector<std::byte> aes_key_;
    std::vector<std::byte> des_key_;
    std::vector<std::byte> iv_;
    bool initialized_ = false;
    std::string last_error_;
    std::uint64_t signature_va_ = 0;
    std::string active_template_name_;
};

} // namespace kvc::security
