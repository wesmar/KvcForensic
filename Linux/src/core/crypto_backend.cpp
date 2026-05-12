#include "core/crypto_backend.h"

#include "core/text_utils.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace kvc::core {

namespace {

constexpr std::size_t kAesBlock = 16;

const EVP_CIPHER* aes_ecb_cipher_for(std::size_t key_len) {
    switch (key_len) {
    case 16: return EVP_aes_128_ecb();
    case 24: return EVP_aes_192_ecb();
    case 32: return EVP_aes_256_ecb();
    default: return nullptr;
    }
}

} // namespace

std::vector<std::byte> CryptoBackend::aes_cfb128_decrypt(
    std::span<const std::byte> key,
    std::span<const std::byte> iv,
    std::span<const std::byte> input) {
    std::vector<std::byte> out;
    if (iv.size() != kAesBlock || input.empty()) return out;
    const EVP_CIPHER* c = aes_ecb_cipher_for(key.size());
    if (!c) return out;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return out;
    if (EVP_EncryptInit_ex(ctx, c, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    out.resize(input.size());
    std::byte counter[kAesBlock];
    std::memcpy(counter, iv.data(), kAesBlock);
    std::byte keystream[kAesBlock];

    for (std::size_t i = 0; i < input.size(); ++i) {
        if ((i % kAesBlock) == 0) {
            int outlen = 0;
            if (EVP_EncryptUpdate(ctx,
                                  reinterpret_cast<unsigned char*>(keystream),
                                  &outlen,
                                  reinterpret_cast<const unsigned char*>(counter),
                                  static_cast<int>(kAesBlock)) != 1 ||
                outlen != static_cast<int>(kAesBlock)) {
                out.clear();
                EVP_CIPHER_CTX_free(ctx);
                return out;
            }
        }
        const auto idx = i % kAesBlock;
        out[i] = static_cast<std::byte>(
            static_cast<unsigned char>(input[i]) ^
            static_cast<unsigned char>(keystream[idx]));
        counter[idx] = input[i];
    }
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<std::byte> CryptoBackend::des3_cbc_decrypt(
    std::span<const std::byte> key,
    std::span<const std::byte> iv,
    std::span<const std::byte> input) {
    std::vector<std::byte> out;
    if (key.size() != 24 || iv.size() != 8 || input.empty() || (input.size() % 8) != 0) return out;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return out;
    if (EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    out.resize(input.size());
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(out.data()),
                          &outlen,
                          reinterpret_cast<const unsigned char*>(input.data()),
                          static_cast<int>(input.size())) != 1) {
        out.clear();
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(out.data() + outlen),
                            &final_len) != 1) {
        out.clear();
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
    out.resize(static_cast<std::size_t>(outlen + final_len));
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<std::byte> CryptoBackend::sha1(std::span<const std::byte> input) {
    std::vector<std::byte> out(SHA_DIGEST_LENGTH);
    if (!SHA1(reinterpret_cast<const unsigned char*>(input.data()),
              input.size(),
              reinterpret_cast<unsigned char*>(out.data()))) {
        return {};
    }
    return out;
}

std::string CryptoBackend::sha1_hex(std::span<const std::byte> input) {
    const auto h = sha1(input);
    if (h.empty()) return {};
    return bytes_to_hex(std::span<const std::byte>(h));
}

} // namespace kvc::core
