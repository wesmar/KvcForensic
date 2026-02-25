#pragma once

#include "core/VirtualMemory.h"
#include "lsa/TemplateRegistry.h"
#include "minidump/MinidumpParser.h"

#include <vector>
#include <cstdint>
#include <string>

namespace KvcForensic::security {

class LsaSecretsExtractor {
public:
    LsaSecretsExtractor(const core::VirtualMemory& vmem, const minidump::MinidumpMetadata& metadata);
    
    // Initialize and extract crypto material
    bool Initialize(std::uint32_t build_number);
    
    // Getters
    const std::vector<std::byte>& GetAesKey() const { return aes_key_; }
    const std::vector<std::byte>& GetDesKey() const { return des_key_; }
    const std::vector<std::byte>& GetIv() const { return iv_; }
    bool IsInitialized() const { return initialized_; }
    const std::wstring& GetLastError() const { return last_error_; }
    
    // Find signature in lsasrv.dll
    std::uint64_t FindSignature();
    
    // Extract AES key from lsasrv.dll memory
    bool ExtractAesKey(std::uint64_t sig_pos);

    // Extract 3DES key from lsasrv.dll memory
    bool ExtractDesKey(std::uint64_t sig_pos);

    // Extract IV from lsasrv.dll memory
    bool ExtractIv(std::uint64_t sig_pos);

    // Decrypt credential blob (auto-selects AES-CFB128 or 3DES-CBC based on size)
    std::vector<std::byte> Decrypt(std::span<const std::byte> encrypted);

private:
    // Read pointer with offset (get_ptr_with_offset from pypykatz)
    std::uint64_t GetPtrWithOffset(std::uint64_t pos);
    
    // Read pointer (get_ptr from pypykatz)
    std::uint64_t GetPtr(std::uint64_t pos);
    
    // Find module by name
    const minidump::ModuleInfo* FindModule(const std::wstring& name);
    
    const core::VirtualMemory& vmem_;
    const minidump::MinidumpMetadata& metadata_;
    
    std::vector<std::byte> aes_key_;  // 16 bytes
    std::vector<std::byte> des_key_;  // 24 bytes (3DES)
    std::vector<std::byte> iv_;       // 16 bytes
    bool initialized_ = false;
    const lsa::templates::LsaSecretsTemplateSpec* template_ = nullptr;
    std::wstring last_error_;
};

} // namespace KvcForensic::security
