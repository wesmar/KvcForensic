#pragma once

#include "core/virtual_memory.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kvc::lsa {

// Heuristic: returns true if the UTF-8 string consists mostly of printable
// characters. Mirrors the Windows IsLikelyReadablePassword check.
bool is_likely_readable_password(const std::string& text);

// Given a decrypted buffer and an optional UTF-16 byte-length hint, fills
// out_password (UTF-8 if printable enough) and out_password_hex (lowercase).
void decode_password_candidate(
    const std::vector<std::byte>& decrypted,
    std::uint16_t utf16_byte_len_hint,
    std::string& out_password,
    std::string& out_password_hex);

} // namespace kvc::lsa
