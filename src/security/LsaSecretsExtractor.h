#pragma once

#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"

#include <vector>
#include <cstdint>
#include <optional>

namespace KvcForensic::security {

// LSA key pattern for Windows 11 24H2+
struct LsaKeyPattern {
    std::vector<std::uint8_t> signature;
    std::int32_t offset_to_IV_ptr = 0;
    std::int32_t offset_to_AES_key_ptr = 0;
    std::int32_t offset_to_DES_key_ptr = 0;
    std::size_t IV_length = 16;
};

// BCRYPT_KEY structure
struct BcryptKey {
    std::uint32_t size = 0;
    std::uint32_t tag = 0;  // 'MSSK' or similar
    std::uint32_t type = 0;
    std::uint32_t unk0 = 0;
    std::uint32_t unk1 = 0;
    std::uint32_t unk2 = 0;
    std::uint32_t unk3 = 0;
    std::uint64_t key_data_ptr = 0;  // Pointer to actual key bytes
};

class LsaSecretsExtractor {
public:
    LsaSecretsExtractor(const core::VirtualMemory& vmem, const minidump::MinidumpMetadata& metadata);
    
    // Initialize and extract crypto material
    bool Initialize();
    
    // Getters
    const std::vector<std::byte>& GetAesKey() const { return aes_key_; }
    const std::vector<std::byte>& GetDesKey() const { return des_key_; }
    const std::vector<std::byte>& GetIv() const { return iv_; }
    bool IsInitialized() const { return initialized_; }
    
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
    
    // Key pattern for Windows 11 24H2+ (build >= 26100)
    static const LsaKeyPattern& GetKeyPattern();
};

} // namespace KvcForensic::security
