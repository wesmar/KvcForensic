#include "security/lsa_secrets_extractor.h"

#include "core/crypto_backend.h"
#include "core/signature_scanner.h"

namespace kvc::security {

LsaSecretsExtractor::LsaSecretsExtractor(
    const core::VirtualMemory& vmem,
    const minidump::DumpMetadata& metadata,
    const core::ModuleIndex& modules,
    const lsa::templates::TemplateRegistry& registry)
    : vmem_(vmem), metadata_(metadata), modules_(modules), registry_(registry) {
    (void)metadata_;
}

std::uint64_t LsaSecretsExtractor::get_ptr_with_offset(std::uint64_t pos) const {
    std::int32_t off = 0;
    if (!vmem_.read_struct(pos, &off)) return 0;
    return pos + 4 + static_cast<std::int64_t>(off);
}

bool LsaSecretsExtractor::extract_iv(std::uint64_t sig_pos,
                                     const lsa::templates::LsaSecretsTemplateSpec& spec) {
    const std::uint64_t ptr_iv = get_ptr_with_offset(sig_pos + static_cast<std::int64_t>(spec.offset_to_iv_ptr));
    if (ptr_iv == 0) return false;
    iv_.assign(spec.iv_length, std::byte{0});
    return vmem_.read_bytes(ptr_iv, spec.iv_length, iv_);
}

bool LsaSecretsExtractor::extract_aes_key(std::uint64_t sig_pos,
                                          const lsa::templates::LsaSecretsTemplateSpec& spec) {
    std::uint64_t ptr_key_handle = get_ptr_with_offset(sig_pos + static_cast<std::int64_t>(spec.offset_to_aes_key_ptr));
    if (ptr_key_handle == 0) return false;
    auto deref = vmem_.read_u64(ptr_key_handle);
    if (!deref || *deref == 0) return false;
    ptr_key_handle = *deref;

    std::uint64_t ptr_key = 0;
    if (!vmem_.read_struct(ptr_key_handle + spec.handle_ptr_key_offset, &ptr_key) || ptr_key == 0) return false;

    std::uint32_t cb_secret = 0;
    if (!vmem_.read_struct(ptr_key + spec.key_cb_secret_offset, &cb_secret)) return false;
    if (cb_secret == 0 || cb_secret > 32) return false;
    aes_key_.assign(cb_secret, std::byte{0});
    return vmem_.read_bytes(ptr_key + spec.key_data_offset, cb_secret, aes_key_);
}

bool LsaSecretsExtractor::extract_des_key(std::uint64_t sig_pos,
                                          const lsa::templates::LsaSecretsTemplateSpec& spec) {
    std::uint64_t ptr_key_handle = get_ptr_with_offset(sig_pos + static_cast<std::int64_t>(spec.offset_to_des_key_ptr));
    if (ptr_key_handle == 0) return false;
    auto deref = vmem_.read_u64(ptr_key_handle);
    if (!deref || *deref == 0) return false;
    ptr_key_handle = *deref;

    std::uint64_t ptr_key = 0;
    if (!vmem_.read_struct(ptr_key_handle + spec.handle_ptr_key_offset, &ptr_key) || ptr_key == 0) return false;

    std::uint32_t cb_secret = 0;
    if (!vmem_.read_struct(ptr_key + spec.key_cb_secret_offset, &cb_secret)) return false;
    if (cb_secret == 0 || cb_secret > 32) return false;
    des_key_.assign(cb_secret, std::byte{0});
    return vmem_.read_bytes(ptr_key + spec.key_data_offset, cb_secret, des_key_);
}

bool LsaSecretsExtractor::initialize(std::uint32_t build_number) {
    if (initialized_) return true;
    last_error_.clear();
    signature_va_ = 0;
    active_template_name_.clear();
    aes_key_.clear(); des_key_.clear(); iv_.clear();

    const auto candidates = registry_.select_lsa_secrets_candidates(build_number);
    if (candidates.empty()) {
        last_error_ = "no LSA secrets template for build " + std::to_string(build_number);
        return false;
    }

    const auto* lsasrv = modules_.find("lsasrv.dll");
    if (!lsasrv) {
        last_error_ = "lsasrv.dll missing in dump";
        return false;
    }

    std::string last_attempt = "no LSA secrets signature matched in lsasrv.dll";
    for (const auto* cand : candidates) {
        if (!cand || cand->signature.empty()) continue;
        const auto matches = core::scan_module(
            vmem_, *lsasrv,
            std::span<const std::uint8_t>(cand->signature.data(), cand->signature.size()));
        if (matches.empty()) continue;

        for (const auto sig_pos : matches) {
            aes_key_.clear(); des_key_.clear(); iv_.clear();

            if (!extract_iv(sig_pos, *cand)) { last_attempt = "extract_iv failed"; continue; }
            if (!extract_aes_key(sig_pos, *cand)) { last_attempt = "extract_aes_key failed"; continue; }
            (void)extract_des_key(sig_pos, *cand);

            initialized_ = true;
            signature_va_ = sig_pos;
            active_template_name_ = cand->name;
            return true;
        }
    }

    last_error_ = last_attempt;
    return false;
}

std::vector<std::byte> LsaSecretsExtractor::decrypt(std::span<const std::byte> encrypted) const {
    if (!initialized_ || iv_.empty() || encrypted.empty()) return {};
    if ((encrypted.size() % 8) != 0) {
        if (aes_key_.empty()) return {};
        return core::CryptoBackend::aes_cfb128_decrypt(aes_key_, iv_, encrypted);
    }
    if (des_key_.empty() || des_key_.size() != 24) return {};
    return core::CryptoBackend::des3_cbc_decrypt(des_key_,
        std::span<const std::byte>(iv_.data(), 8), encrypted);
}

} // namespace kvc::security
