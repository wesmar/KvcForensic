#include "security/LsaSecretsExtractor.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

// Windows BCrypt header for AES decryption
// Must define WIN32_NO_STATUS before including bcrypt.h to avoid NTSTATUS redefinition
#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>
#undef WIN32_NO_STATUS
#pragma comment(lib, "bcrypt.lib")

namespace KvcForensic::security {

// BCRYPT_KEY_DATA_BLOB_HEADER for raw key import
struct BcryptKeyDataBlobHeader {
    ULONG dwMagic = 0x4d42444b;  // BCRYPT_KEY_DATA_BLOB_MAGIC
    ULONG dwVersion = 1;
    ULONG cbKeyData = 0;
};

namespace {

// AES block size
constexpr size_t AES_BLOCK_SIZE = 16;

// Simple AES-CFB128 implementation (since BCrypt only supports CFB8)
// In CFB128: counter = previous ciphertext block (not keystream!)
void AES_CFB128_Decrypt(
    BCRYPT_KEY_HANDLE hKey,
    const std::vector<std::byte>& iv,
    const std::vector<std::byte>& input,
    std::vector<std::byte>& output) {
    
    output.resize(input.size());
    std::vector<std::byte> counter = iv;
    std::vector<std::byte> keystream(AES_BLOCK_SIZE);
    ULONG cbResult = 0;
    
    for (size_t i = 0; i < input.size(); i++) {
        if (i % AES_BLOCK_SIZE == 0) {
            // Encrypt counter to generate keystream
            BCryptEncrypt(hKey, 
                         reinterpret_cast<PUCHAR>(counter.data()), 
                         static_cast<ULONG>(AES_BLOCK_SIZE),
                         NULL, NULL, 0,
                         reinterpret_cast<PUCHAR>(keystream.data()), 
                         static_cast<ULONG>(AES_BLOCK_SIZE), 
                         &cbResult, 
                         0);
        }
        // XOR with keystream to decrypt
        output[i] = static_cast<std::byte>(input[i] ^ keystream[i % AES_BLOCK_SIZE]);
        
        // Update counter with ciphertext (not keystream!) - this is the CFB bug fix
        counter[i % AES_BLOCK_SIZE] = input[i];
    }
}

} // namespace

const LsaKeyPattern& LsaSecretsExtractor::GetKeyPattern() {
    // Windows 11 24H2+ (build >= 26100) - LSA_x64_9 template from pypykatz
    static const LsaKeyPattern pattern = {
        // Signature: 16 bytes (not 13!)
        {0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
        71,   // offset_to_IV_ptr (not 63)
        16,   // offset_to_AES_key_ptr (not 25)
        -89,  // offset_to_DES_key_ptr
        16    // IV_length
    };
    return pattern;
}

LsaSecretsExtractor::LsaSecretsExtractor(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata)
    : vmem_(vmem), metadata_(metadata) {}

const minidump::ModuleInfo* LsaSecretsExtractor::FindModule(const std::wstring& name) {
    for (const auto& mod : metadata_.modules) {
        std::wstring mod_name_lower = mod.name;
        std::wstring search_name_lower = name;
        std::transform(mod_name_lower.begin(), mod_name_lower.end(), mod_name_lower.begin(), ::towlower);
        std::transform(search_name_lower.begin(), search_name_lower.end(), search_name_lower.begin(), ::towlower);
        if (mod_name_lower.find(search_name_lower) != std::wstring::npos) {
            return &mod;
        }
    }
    return nullptr;
}

std::uint64_t LsaSecretsExtractor::FindSignature() {
    const auto& pattern = GetKeyPattern();
    
    const minidump::ModuleInfo* lsasrv = FindModule(L"lsasrv.dll");
    if (!lsasrv) return 0;
    
    // Search in memory ranges that overlap with lsasrv.dll
    for (const auto& range : metadata_.memory_ranges) {
        std::uint64_t start = std::max(range.start_vva, static_cast<std::uint64_t>(lsasrv->base_address));
        std::uint64_t end = std::min(range.start_vva + range.size, static_cast<std::uint64_t>(lsasrv->base_address + lsasrv->size));
        
        if (start >= end) continue;
        
        std::vector<std::byte> chunk(end - start);
        if (!vmem_.ReadBytes(start, chunk.size(), chunk)) continue;
        
        // Search for signature
        for (std::size_t i = 0; i <= chunk.size() - pattern.signature.size(); ++i) {
            if (std::memcmp(chunk.data() + i, pattern.signature.data(), pattern.signature.size()) == 0) {
                return start + i;
            }
        }
    }
    
    return 0;
}

std::uint64_t LsaSecretsExtractor::GetPtrWithOffset(std::uint64_t pos) {
    std::int32_t offset = 0;
    if (!vmem_.ReadStruct(pos, &offset)) return 0;
    return pos + 4 + offset;
}

std::uint64_t LsaSecretsExtractor::GetPtr(std::uint64_t pos) {
    std::uint64_t ptr = 0;
    vmem_.ReadStruct(pos, &ptr);
    return ptr;
}

bool LsaSecretsExtractor::ExtractAesKey(std::uint64_t sig_pos) {
    const auto& pattern = GetKeyPattern();
    
    // Step 1: Get pointer to AES key structure (address of global variable g_pAesKey)
    std::uint64_t ptr_key_handle = GetPtrWithOffset(sig_pos + pattern.offset_to_AES_key_ptr);
    if (ptr_key_handle == 0) return false;
    
    // Step 2: Dereference to get the VALUE of g_pAesKey (address of KIWI_BCRYPT_HANDLE_KEY)
    // This is the missing dereference!
    ptr_key_handle = GetPtr(ptr_key_handle);
    if (ptr_key_handle == 0) return false;
    
    // Step 3: Read KIWI_BCRYPT_HANDLE_KEY structure
    // Layout: size (4), tag (4), hAlgorithm (8), ptr_key (8)
    std::uint32_t handle_size = 0;
    std::uint32_t handle_tag = 0;
    std::uint64_t h_algorithm = 0;
    std::uint64_t ptr_key = 0;
    
    if (!vmem_.ReadStruct(ptr_key_handle, &handle_size)) return false;
    if (!vmem_.ReadStruct(ptr_key_handle + 4, &handle_tag)) return false;
    if (!vmem_.ReadStruct(ptr_key_handle + 8, &h_algorithm)) return false;
    if (!vmem_.ReadStruct(ptr_key_handle + 16, &ptr_key)) return false;
    
    if (ptr_key == 0) return false;
    
    // Step 4: ptr_key points to KIWI_BCRYPT_KEY81 structure
    // Layout: size (4), tag (4), ..., cbSecret (4 at offset 56), data[] (at offset 60)
    std::uint32_t key_size = 0;
    std::uint32_t key_tag = 0;
    std::uint32_t cb_secret = 0;
    
    if (!vmem_.ReadStruct(ptr_key, &key_size)) return false;
    if (!vmem_.ReadStruct(ptr_key + 4, &key_tag)) return false;
    if (!vmem_.ReadStruct(ptr_key + 56, &cb_secret)) return false;
    
    if (cb_secret == 0 || cb_secret > 32) return false;
    
    // Step 5: Read key data from offset 60
    aes_key_.resize(cb_secret);
    if (!vmem_.ReadBytes(ptr_key + 60, cb_secret, aes_key_)) return false;
    
    return true;
}

bool LsaSecretsExtractor::ExtractDesKey(std::uint64_t sig_pos) {
    const auto& pattern = GetKeyPattern();

    // Same dereference chain as AES key extraction
    std::uint64_t ptr_key_handle = GetPtrWithOffset(sig_pos + pattern.offset_to_DES_key_ptr);
    if (ptr_key_handle == 0) return false;

    ptr_key_handle = GetPtr(ptr_key_handle);
    if (ptr_key_handle == 0) return false;

    // KIWI_BCRYPT_HANDLE_KEY: size(4) + tag(4) + hAlgorithm(8) + ptr_key(8)
    std::uint64_t ptr_key = 0;
    if (!vmem_.ReadStruct(ptr_key_handle + 16, &ptr_key)) return false;
    if (ptr_key == 0) return false;

    // KIWI_BCRYPT_KEY81: cbSecret at offset 56, data at offset 60
    std::uint32_t cb_secret = 0;
    if (!vmem_.ReadStruct(ptr_key + 56, &cb_secret)) return false;
    if (cb_secret == 0 || cb_secret > 32) return false;

    des_key_.resize(cb_secret);
    if (!vmem_.ReadBytes(ptr_key + 60, cb_secret, des_key_)) return false;

    return true;
}

bool LsaSecretsExtractor::ExtractIv(std::uint64_t sig_pos) {
    const auto& pattern = GetKeyPattern();
    
    // Get pointer to IV
    std::uint64_t ptr_iv = GetPtrWithOffset(sig_pos + pattern.offset_to_IV_ptr);
    if (ptr_iv == 0) return false;
    
    // Read IV (16 bytes)
    iv_.resize(pattern.IV_length);
    if (!vmem_.ReadBytes(ptr_iv, pattern.IV_length, iv_)) return false;
    
    return true;
}

bool LsaSecretsExtractor::Initialize() {
    if (initialized_) return true;
    
    std::uint64_t sig_pos = FindSignature();
    if (sig_pos == 0) return false;
    
    if (!ExtractIv(sig_pos)) return false;
    if (!ExtractAesKey(sig_pos)) return false;
    ExtractDesKey(sig_pos); // Optional - some dumps may not have DES key

    initialized_ = true;
    return true;
}

std::vector<std::byte> LsaSecretsExtractor::Decrypt(std::span<const std::byte> encrypted) {
    std::vector<std::byte> decrypted;

    if (!initialized_ || iv_.empty() || encrypted.empty()) {
        return decrypted;
    }

    size_t size = encrypted.size();

    // pypykatz logic: size % 8 != 0 → AES-CFB128, size % 8 == 0 → 3DES-CBC
    if (size % 8 != 0) {
        // AES-CFB128 path
        if (aes_key_.empty()) return decrypted;

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (status != 0) return decrypted;

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return decrypted; }

        std::vector<std::byte> key_blob(sizeof(BcryptKeyDataBlobHeader) + aes_key_.size());
        auto* header = reinterpret_cast<BcryptKeyDataBlobHeader*>(key_blob.data());
        header->dwMagic = 0x4d42444b;
        header->dwVersion = 1;
        header->cbKeyData = static_cast<ULONG>(aes_key_.size());
        std::memcpy(key_blob.data() + sizeof(BcryptKeyDataBlobHeader), aes_key_.data(), aes_key_.size());

        status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0,
                                 reinterpret_cast<PUCHAR>(key_blob.data()),
                                 static_cast<ULONG>(key_blob.size()), 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return decrypted; }

        std::vector<std::byte> iv_vec(iv_.begin(), iv_.end());
        std::vector<std::byte> encrypted_vec(encrypted.begin(), encrypted.end());
        AES_CFB128_Decrypt(hKey, iv_vec, encrypted_vec, decrypted);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    } else {
        // 3DES-CBC path
        if (des_key_.empty()) return decrypted;

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_3DES_ALGORITHM, NULL, 0);
        if (status != 0) return decrypted;

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return decrypted; }

        std::vector<std::byte> key_blob(sizeof(BcryptKeyDataBlobHeader) + des_key_.size());
        auto* header = reinterpret_cast<BcryptKeyDataBlobHeader*>(key_blob.data());
        header->dwMagic = 0x4d42444b;
        header->dwVersion = 1;
        header->cbKeyData = static_cast<ULONG>(des_key_.size());
        std::memcpy(key_blob.data() + sizeof(BcryptKeyDataBlobHeader), des_key_.data(), des_key_.size());

        status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0,
                                 reinterpret_cast<PUCHAR>(key_blob.data()),
                                 static_cast<ULONG>(key_blob.size()), 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return decrypted; }

        // 3DES-CBC uses first 8 bytes of IV
        std::vector<UCHAR> iv8(8);
        std::memcpy(iv8.data(), iv_.data(), 8);
        decrypted.resize(size);
        ULONG cbResult = 0;

        status = BCryptDecrypt(hKey,
                               const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(encrypted.data())),
                               static_cast<ULONG>(size),
                               NULL,
                               iv8.data(), static_cast<ULONG>(iv8.size()),
                               reinterpret_cast<PUCHAR>(decrypted.data()),
                               static_cast<ULONG>(size),
                               &cbResult, 0);
        if (status != 0) {
            decrypted.clear();
        } else {
            decrypted.resize(cbResult);
        }

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return decrypted;
}

} // namespace KvcForensic::security
