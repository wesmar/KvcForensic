#include "lsa/reader_utils.h"

#include "core/text_utils.h"

#include <algorithm>

namespace kvc::lsa {

bool is_likely_readable_password(const std::string& text) {
    if (text.empty()) return false;
    if (text.size() > 1024) return false;
    std::size_t printable = 0;
    for (const unsigned char ch : text) {
        if (ch == 0) return false;
        if (ch == '\r' || ch == '\n' || ch == '\t' || (ch >= 0x20 && ch < 0x7f) || ch >= 0x80) {
            ++printable;
        }
    }
    return printable * 100 >= text.size() * 85;
}

void decode_password_candidate(
    const std::vector<std::byte>& decrypted,
    std::uint16_t utf16_byte_len_hint,
    std::string& out_password,
    std::string& out_password_hex) {
    out_password.clear();
    out_password_hex.clear();
    if (decrypted.empty()) return;

    std::size_t take = decrypted.size();
    if (utf16_byte_len_hint > 0)
        take = std::min<std::size_t>(take, utf16_byte_len_hint);
    if ((take & 1u) != 0u) --take;
    if (take == 0) return;

    const std::size_t hex_cap = std::min<std::size_t>(take, 4096);
    out_password_hex = core::bytes_to_hex(
        std::span<const std::byte>(decrypted.data(), hex_cap));
    if (hex_cap < take) out_password_hex += "...";

    std::string decoded = core::utf16le_to_utf8(
        std::span<const std::byte>(decrypted.data(), take));
    while (!decoded.empty() && decoded.back() == '\0') decoded.pop_back();
    if (is_likely_readable_password(decoded)) out_password = std::move(decoded);
}

} // namespace kvc::lsa
