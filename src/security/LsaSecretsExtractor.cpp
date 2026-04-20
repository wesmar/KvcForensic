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

std::vector<std::uint64_t> FindSignatureMatches(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    const minidump::ModuleInfo& module,
    const std::vector<std::uint8_t>& signature) {
    std::vector<std::uint64_t> matches;
    if (signature.empty()) {
        return matches;
    }

    for (const auto& range : metadata.memory_ranges) {
        std::uint64_t start = std::max(range.start_vva, static_cast<std::uint64_t>(module.base_address));
        std::uint64_t end = std::min(range.start_vva + range.size, static_cast<std::uint64_t>(module.base_address + module.size));

        if (start >= end || (end - start) < signature.size()) {
            continue;
        }

        std::vector<std::byte> chunk(end - start);
        if (!vmem.ReadBytes(start, chunk.size(), chunk)) {
            continue;
        }

        for (std::size_t i = 0; i <= chunk.size() - signature.size(); ++i) {
            if (std::memcmp(chunk.data() + i, signature.data(), signature.size()) == 0) {
                matches.push_back(start + i);
            }
        }
    }

    return matches;
}

std::uint64_t LsaSecretsExtractor::FindSignature() {
    if (template_ == nullptr || template_->signature.empty()) {
        return 0;
    }
    
    const minidump::ModuleInfo* lsasrv = FindModule(L"lsasrv.dll");
    if (!lsasrv) return 0;

    const auto matches = FindSignatureMatches(vmem_, metadata_, *lsasrv, template_->signature);
    return matches.empty() ? 0 : matches.front();
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
    // Step 1: Get pointer to AES key structure (address of global variable g_pAesKey)
    std::uint64_t ptr_key_handle = GetPtrWithOffset(sig_pos + template_->offset_to_aes_key_ptr);
    if (ptr_key_handle == 0) return false;
    
    // Step 2: Dereference to get the VALUE of g_pAesKey (address of KIWI_BCRYPT_HANDLE_KEY)
    // This is the missing dereference!
    ptr_key_handle = GetPtr(ptr_key_handle);
    if (ptr_key_handle == 0) return false;
    
    // Step 3: Read KIWI_BCRYPT_HANDLE_KEY structure.
    std::uint64_t ptr_key = 0;
    
    if (!vmem_.ReadStruct(ptr_key_handle + template_->handle_ptr_key_offset, &ptr_key)) return false;
    
    if (ptr_key == 0) return false;
    
    // Step 4: ptr_key points to KIWI_BCRYPT_KEY* structure.
    std::uint32_t key_size = 0;
    std::uint32_t key_tag = 0;
    std::uint32_t cb_secret = 0;
    
    if (!vmem_.ReadStruct(ptr_key, &key_size)) return false;
    if (!vmem_.ReadStruct(ptr_key + 4, &key_tag)) return false;
    if (!vmem_.ReadStruct(ptr_key + template_->key_cb_secret_offset, &cb_secret)) return false;
    
    if (cb_secret == 0 || cb_secret > 32) return false;
    
    // Step 5: Read key material bytes.
    aes_key_.resize(cb_secret);
    if (!vmem_.ReadBytes(ptr_key + template_->key_data_offset, cb_secret, aes_key_)) return false;
    
    return true;
}

bool LsaSecretsExtractor::ExtractDesKey(std::uint64_t sig_pos) {
    // Same dereference chain as AES key extraction
    std::uint64_t ptr_key_handle = GetPtrWithOffset(sig_pos + template_->offset_to_des_key_ptr);
    if (ptr_key_handle == 0) return false;

    ptr_key_handle = GetPtr(ptr_key_handle);
    if (ptr_key_handle == 0) return false;

    std::uint64_t ptr_key = 0;
    if (!vmem_.ReadStruct(ptr_key_handle + template_->handle_ptr_key_offset, &ptr_key)) return false;
    if (ptr_key == 0) return false;

    std::uint32_t cb_secret = 0;
    if (!vmem_.ReadStruct(ptr_key + template_->key_cb_secret_offset, &cb_secret)) return false;
    if (cb_secret == 0 || cb_secret > 32) return false;

    des_key_.resize(cb_secret);
    if (!vmem_.ReadBytes(ptr_key + template_->key_data_offset, cb_secret, des_key_)) return false;

    return true;
}

bool LsaSecretsExtractor::ExtractIv(std::uint64_t sig_pos) {
    // Get pointer to IV
    std::uint64_t ptr_iv = GetPtrWithOffset(sig_pos + template_->offset_to_iv_ptr);
    if (ptr_iv == 0) return false;
    
    // Read IV (16 bytes)
    iv_.resize(template_->iv_length);
    if (!vmem_.ReadBytes(ptr_iv, template_->iv_length, iv_)) return false;
    
    return true;
}

bool LsaSecretsExtractor::Initialize(const std::uint32_t build_number) {
    if (initialized_) return true;
    last_error_.clear();

    const auto candidates = lsa::templates::SelectLsaSecretsTemplateCandidatesX64(build_number);
    if (candidates.empty()) {
        last_error_ = L"No LSA secrets template for build " + std::to_wstring(build_number) + L".";
        return false;
    }

    const minidump::ModuleInfo* lsasrv = FindModule(L"lsasrv.dll");
    if (!lsasrv) {
        last_error_ = L"lsasrv.dll not present in dump module list.";
        return false;
    }

    std::wstring last_attempt_error = L"LSA secrets signature not found in lsasrv.dll memory ranges.";
    for (const auto* candidate : candidates) {
        if (candidate == nullptr || candidate->signature.empty()) {
            continue;
        }

        const auto matches = FindSignatureMatches(vmem_, metadata_, *lsasrv, candidate->signature);
        if (matches.empty()) {
            continue;
        }

        for (const auto sig_pos : matches) {
            template_ = candidate;
            aes_key_.clear();
            des_key_.clear();
            iv_.clear();

            if (!ExtractIv(sig_pos)) {
                last_attempt_error = L"Failed to extract LSA IV.";
                continue;
            }
            if (!ExtractAesKey(sig_pos)) {
                last_attempt_error = L"Failed to extract LSA AES key.";
                continue;
            }
            ExtractDesKey(sig_pos); // Optional - some dumps may not have DES key

            initialized_ = true;
            last_error_.clear();
            return true;
        }
    }

    template_ = nullptr;
    last_error_ = last_attempt_error;
    return false;
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
