#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kvc::core {

// Thin, OpenSSL-backed crypto helpers needed by LSA package walkers.
// All functions are stateless and silent on failure (return empty vector / "").
class CryptoBackend {
public:
    // AES-CFB128 decryption (mimics Windows BCrypt CFB128 mode where the
    // counter is updated with ciphertext, not keystream). key length must be
    // 16, 24 or 32; iv length must be 16; produces output the same size as
    // input. Returns empty vector on failure.
    static std::vector<std::byte> aes_cfb128_decrypt(
        std::span<const std::byte> key,
        std::span<const std::byte> iv,
        std::span<const std::byte> input);

    // 3DES (TripleDES) CBC decryption. key must be 24 bytes, iv 8 bytes.
    // Input must be multiple of 8 bytes. Returns empty vector on failure.
    static std::vector<std::byte> des3_cbc_decrypt(
        std::span<const std::byte> key,
        std::span<const std::byte> iv,
        std::span<const std::byte> input);

    // SHA1 digest. Returns 20-byte vector, or empty on failure.
    static std::vector<std::byte> sha1(std::span<const std::byte> input);

    // SHA1 hex (lowercase). Empty string on failure.
    static std::string sha1_hex(std::span<const std::byte> input);
};

} // namespace kvc::core
