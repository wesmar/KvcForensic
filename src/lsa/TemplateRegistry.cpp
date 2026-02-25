#include "lsa/TemplateRegistry.h"

#include <Windows.h>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace KvcForensic::lsa::templates {

namespace {

constexpr std::uint32_t kBuildMax = std::numeric_limits<std::uint32_t>::max();

std::vector<MsvTemplateSpec> g_MsvX64Templates = {
};

std::vector<WdigestTemplateSpec> g_WdigestX64Templates = {
};

std::vector<KerberosTemplateSpec> g_KerberosX64Templates = {
};

std::vector<DpapiTemplateSpec> g_DpapiX64Templates = {
};

std::vector<LsaSecretsTemplateSpec> g_LsaSecretsX64Templates = {
};

std::wstring g_RegistryInitError;

template <typename TSpec>
const TSpec* SelectByBuild(const std::vector<TSpec>& table, const std::uint32_t build_number) {
    for (const auto& spec : table) {
        if (build_number >= spec.min_build && build_number <= spec.max_build) {
            return &spec;
        }
    }
    return nullptr;
}

std::vector<std::uint8_t> ParseHex(const std::string& hex) {
    std::vector<std::uint8_t> bytes;
    if ((hex.size() % 2) != 0) {
        return bytes;
    }

    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte = 0;
        const char hi = hex[i];
        const char lo = hex[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(hi)) || !std::isxdigit(static_cast<unsigned char>(lo))) {
            return std::vector<std::uint8_t>();
        }
        const std::string byteString{ hi, lo };
        byte = static_cast<unsigned int>(strtoul(byteString.c_str(), nullptr, 16));
        bytes.push_back(static_cast<std::uint8_t>(byte));
    }
    return bytes;
}

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

class JsonCursor {
public:
    explicit JsonCursor(const std::string& text)
        : text_(text) {}

    bool ok() const { return ok_; }
    bool end() {
        SkipWs();
        return pos_ >= text_.size();
    }

    bool Consume(const char ch) {
        SkipWs();
        if (pos_ < text_.size() && text_[pos_] == ch) {
            ++pos_;
            return true;
        }
        return false;
    }

    bool Expect(const char ch) {
        if (!Consume(ch)) {
            ok_ = false;
            return false;
        }
        return true;
    }

    bool ParseString(std::string& out) {
        SkipWs();
        if (pos_ >= text_.size() || text_[pos_] != '"') {
            ok_ = false;
            return false;
        }
        ++pos_;
        out.clear();
        while (pos_ < text_.size()) {
            const char ch = text_[pos_++];
            if (ch == '"') {
                return true;
            }
            if (ch == '\\') {
                if (pos_ >= text_.size()) {
                    ok_ = false;
                    return false;
                }
                const char esc = text_[pos_++];
                switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u':
                    // Keep parser tiny: preserve \uXXXX escapes as '?'.
                    if (pos_ + 4 > text_.size()) {
                        ok_ = false;
                        return false;
                    }
                    pos_ += 4;
                    out.push_back('?');
                    break;
                default:
                    ok_ = false;
                    return false;
                }
                continue;
            }
            out.push_back(ch);
        }
        ok_ = false;
        return false;
    }

    bool ParseBool(bool& out) {
        SkipWs();
        if (MatchLiteral("true")) {
            out = true;
            return true;
        }
        if (MatchLiteral("false")) {
            out = false;
            return true;
        }
        ok_ = false;
        return false;
    }

    bool ParseInt(int& out) {
        std::int64_t v = 0;
        if (!ParseSignedInteger(v)) {
            return false;
        }
        if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) {
            ok_ = false;
            return false;
        }
        out = static_cast<int>(v);
        return true;
    }

    bool ParseUint32(std::uint32_t& out) {
        std::uint64_t v = 0;
        if (!ParseUnsignedInteger(v)) {
            return false;
        }
        if (v > std::numeric_limits<std::uint32_t>::max()) {
            ok_ = false;
            return false;
        }
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    bool ParseSize(std::size_t& out) {
        std::uint64_t v = 0;
        if (!ParseUnsignedInteger(v)) {
            return false;
        }
        if (v > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            ok_ = false;
            return false;
        }
        out = static_cast<std::size_t>(v);
        return true;
    }

    bool SkipValue() {
        SkipWs();
        if (pos_ >= text_.size()) {
            ok_ = false;
            return false;
        }
        const char ch = text_[pos_];
        if (ch == '{') {
            return SkipObject();
        }
        if (ch == '[') {
            return SkipArray();
        }
        if (ch == '"') {
            std::string tmp;
            return ParseString(tmp);
        }
        if (ch == 't' || ch == 'f') {
            bool tmp = false;
            return ParseBool(tmp);
        }
        if (ch == 'n') {
            return MatchLiteral("null");
        }
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch))) {
            return SkipNumber();
        }
        ok_ = false;
        return false;
    }

private:
    void SkipWs() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
    }

    bool MatchLiteral(const char* literal) {
        const std::size_t len = std::strlen(literal);
        if (pos_ + len > text_.size()) {
            return false;
        }
        if (text_.compare(pos_, len, literal) == 0) {
            pos_ += len;
            return true;
        }
        return false;
    }

    bool ParseSignedInteger(std::int64_t& out) {
        SkipWs();
        const std::size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-') {
            ++pos_;
        }
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ok_ = false;
            return false;
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
        const std::string_view token(text_.data() + start, pos_ - start);
        std::int64_t value = 0;
        const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
        if (ec != std::errc() || ptr != (token.data() + token.size())) {
            ok_ = false;
            return false;
        }
        out = value;
        return true;
    }

    bool ParseUnsignedInteger(std::uint64_t& out) {
        SkipWs();
        const std::size_t start = pos_;
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ok_ = false;
            return false;
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
        const std::string_view token(text_.data() + start, pos_ - start);
        std::uint64_t value = 0;
        const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
        if (ec != std::errc() || ptr != (token.data() + token.size())) {
            ok_ = false;
            return false;
        }
        out = value;
        return true;
    }

    bool SkipNumber() {
        SkipWs();
        const std::size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-') {
            ++pos_;
        }
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ok_ = false;
            return false;
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
        // Reject floating-point notation in config to keep parser narrow.
        if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ok_ = false;
            return false;
        }
        return pos_ > start;
    }

    bool SkipObject() {
        if (!Expect('{')) {
            return false;
        }
        if (Consume('}')) {
            return true;
        }
        while (ok_) {
            std::string key;
            if (!ParseString(key) || !Expect(':') || !SkipValue()) {
                return false;
            }
            if (Consume('}')) {
                return true;
            }
            if (!Expect(',')) {
                return false;
            }
        }
        return false;
    }

    bool SkipArray() {
        if (!Expect('[')) {
            return false;
        }
        if (Consume(']')) {
            return true;
        }
        while (ok_) {
            if (!SkipValue()) {
                return false;
            }
            if (Consume(']')) {
                return true;
            }
            if (!Expect(',')) {
                return false;
            }
        }
        return false;
    }

    const std::string& text_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

template<typename TItem, typename TParser>
bool ParseArray(JsonCursor& c, std::vector<TItem>& out, TParser parser) {
    if (!c.Expect('[')) {
        return false;
    }
    out.clear();
    if (c.Consume(']')) {
        return true;
    }
    while (c.ok()) {
        TItem item;
        if (!parser(c, item)) {
            return false;
        }
        out.push_back(std::move(item));
        if (c.Consume(']')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

bool ParseSizeArray(JsonCursor& c, std::vector<std::size_t>& out) {
    if (!c.Expect('[')) {
        return false;
    }
    out.clear();
    if (c.Consume(']')) {
        return true;
    }
    while (c.ok()) {
        std::size_t value = 0;
        if (!c.ParseSize(value)) {
            return false;
        }
        out.push_back(value);
        if (c.Consume(']')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

bool ParseMsvTemplate(JsonCursor& c, MsvTemplateSpec& spec) {
    spec.max_build = kBuildMax;
    if (!c.Expect('{')) {
        return false;
    }
    if (c.Consume('}')) {
        return true;
    }
    while (c.ok()) {
        std::string key;
        if (!c.ParseString(key) || !c.Expect(':')) {
            return false;
        }
        if (key == "name") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.name = Utf8ToWide(v);
        } else if (key == "min_build") {
            if (!c.ParseUint32(spec.min_build)) return false;
        } else if (key == "max_build") {
            if (!c.ParseUint32(spec.max_build)) return false;
        } else if (key == "signature") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.signature = ParseHex(v);
        } else if (key == "first_entry_offset") {
            if (!c.ParseInt(spec.first_entry_offset)) return false;
        } else if (key == "offset2") {
            if (!c.ParseInt(spec.offset2)) return false;
        } else if (key == "first_entry_offset_correction") {
            if (!c.ParseInt(spec.first_entry_offset_correction)) return false;
        } else if (key == "session_luid_offset") {
            if (!c.ParseSize(spec.session_luid_offset)) return false;
        } else if (key == "session_username_offset") {
            if (!c.ParseSize(spec.session_username_offset)) return false;
        } else if (key == "session_domain_offset") {
            if (!c.ParseSize(spec.session_domain_offset)) return false;
        } else if (key == "session_sid_ptr_offset") {
            if (!c.ParseSize(spec.session_sid_ptr_offset)) return false;
        } else if (key == "session_credentials_ptr_offset") {
            if (!c.ParseSize(spec.session_credentials_ptr_offset)) return false;
        } else if (key == "session_credman_ptr_offset") {
            if (!c.ParseSize(spec.session_credman_ptr_offset)) return false;
        } else if (key == "parser_support") {
            if (!c.ParseBool(spec.parser_support)) return false;
        } else if (!c.SkipValue()) {
            return false;
        }

        if (c.Consume('}')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

bool ParseWdigestTemplate(JsonCursor& c, WdigestTemplateSpec& spec) {
    spec.max_build = kBuildMax;
    if (!c.Expect('{')) {
        return false;
    }
    if (c.Consume('}')) {
        return true;
    }
    while (c.ok()) {
        std::string key;
        if (!c.ParseString(key) || !c.Expect(':')) {
            return false;
        }
        if (key == "name") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.name = Utf8ToWide(v);
        } else if (key == "min_build") {
            if (!c.ParseUint32(spec.min_build)) return false;
        } else if (key == "max_build") {
            if (!c.ParseUint32(spec.max_build)) return false;
        } else if (key == "signature") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.signature = ParseHex(v);
        } else if (key == "first_entry_offset") {
            if (!c.ParseInt(spec.first_entry_offset)) return false;
        } else if (key == "primary_offset") {
            if (!c.ParseSize(spec.primary_offset)) return false;
        } else if (!c.SkipValue()) {
            return false;
        }

        if (c.Consume('}')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

bool ParseKerberosTemplate(JsonCursor& c, KerberosTemplateSpec& spec) {
    spec.max_build = kBuildMax;
    if (!c.Expect('{')) {
        return false;
    }
    if (c.Consume('}')) {
        return true;
    }
    while (c.ok()) {
        std::string key;
        if (!c.ParseString(key) || !c.Expect(':')) {
            return false;
        }
        if (key == "name") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.name = Utf8ToWide(v);
        } else if (key == "min_build") {
            if (!c.ParseUint32(spec.min_build)) return false;
        } else if (key == "max_build") {
            if (!c.ParseUint32(spec.max_build)) return false;
        } else if (key == "signature") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.signature = ParseHex(v);
        } else if (key == "first_entry_offset") {
            if (!c.ParseInt(spec.first_entry_offset)) return false;
        } else if (key == "session_luid_offset") {
            if (!c.ParseSize(spec.session_luid_offset)) return false;
        } else if (key == "session_username_offset") {
            if (!c.ParseSize(spec.session_username_offset)) return false;
        } else if (key == "session_domain_offset") {
            if (!c.ParseSize(spec.session_domain_offset)) return false;
        } else if (key == "session_password_ustr_offset") {
            if (!c.ParseSize(spec.session_password_ustr_offset)) return false;
        } else if (key == "session_luid_fallback_offsets") {
            if (!ParseSizeArray(c, spec.session_luid_fallback_offsets)) return false;
        } else if (key == "ticket_list_offsets") {
            if (!ParseSizeArray(c, spec.ticket_list_offsets)) return false;
        } else if (key == "ticket_service_name_offset") {
            if (!c.ParseSize(spec.ticket_service_name_offset)) return false;
        } else if (key == "ticket_target_name_offset") {
            if (!c.ParseSize(spec.ticket_target_name_offset)) return false;
        } else if (key == "ticket_client_name_offset") {
            if (!c.ParseSize(spec.ticket_client_name_offset)) return false;
        } else if (key == "ticket_flags_offset") {
            if (!c.ParseSize(spec.ticket_flags_offset)) return false;
        } else if (key == "ticket_key_type_offset") {
            if (!c.ParseSize(spec.ticket_key_type_offset)) return false;
        } else if (key == "ticket_enc_type_offset") {
            if (!c.ParseSize(spec.ticket_enc_type_offset)) return false;
        } else if (key == "ticket_kvno_offset") {
            if (!c.ParseSize(spec.ticket_kvno_offset)) return false;
        } else if (key == "ticket_buffer_len_offset") {
            if (!c.ParseSize(spec.ticket_buffer_len_offset)) return false;
        } else if (key == "ticket_buffer_ptr_offset") {
            if (!c.ParseSize(spec.ticket_buffer_ptr_offset)) return false;
        } else if (key == "external_name_first_string_offset") {
            if (!c.ParseSize(spec.external_name_first_string_offset)) return false;
        } else if (!c.SkipValue()) {
            return false;
        }

        if (c.Consume('}')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

bool ParseDpapiTemplate(JsonCursor& c, DpapiTemplateSpec& spec) {
    spec.max_build = kBuildMax;
    if (!c.Expect('{')) {
        return false;
    }
    if (c.Consume('}')) {
        return true;
    }
    while (c.ok()) {
        std::string key;
        if (!c.ParseString(key) || !c.Expect(':')) {
            return false;
        }
        if (key == "name") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.name = Utf8ToWide(v);
        } else if (key == "min_build") {
            if (!c.ParseUint32(spec.min_build)) return false;
        } else if (key == "max_build") {
            if (!c.ParseUint32(spec.max_build)) return false;
        } else if (key == "signature") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.signature = ParseHex(v);
        } else if (key == "first_entry_offset") {
            if (!c.ParseInt(spec.first_entry_offset)) return false;
        } else if (!c.SkipValue()) {
            return false;
        }

        if (c.Consume('}')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

bool ParseLsaSecretsTemplate(JsonCursor& c, LsaSecretsTemplateSpec& spec) {
    spec.max_build = kBuildMax;
    if (!c.Expect('{')) {
        return false;
    }
    if (c.Consume('}')) {
        return true;
    }
    while (c.ok()) {
        std::string key;
        if (!c.ParseString(key) || !c.Expect(':')) {
            return false;
        }
        if (key == "name") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.name = Utf8ToWide(v);
        } else if (key == "min_build") {
            if (!c.ParseUint32(spec.min_build)) return false;
        } else if (key == "max_build") {
            if (!c.ParseUint32(spec.max_build)) return false;
        } else if (key == "signature") {
            std::string v;
            if (!c.ParseString(v)) return false;
            spec.signature = ParseHex(v);
        } else if (key == "offset_to_iv_ptr") {
            if (!c.ParseInt(spec.offset_to_iv_ptr)) return false;
        } else if (key == "offset_to_aes_key_ptr") {
            if (!c.ParseInt(spec.offset_to_aes_key_ptr)) return false;
        } else if (key == "offset_to_des_key_ptr") {
            if (!c.ParseInt(spec.offset_to_des_key_ptr)) return false;
        } else if (key == "iv_length") {
            if (!c.ParseSize(spec.iv_length)) return false;
        } else if (key == "handle_ptr_key_offset") {
            if (!c.ParseSize(spec.handle_ptr_key_offset)) return false;
        } else if (key == "key_cb_secret_offset") {
            if (!c.ParseSize(spec.key_cb_secret_offset)) return false;
        } else if (key == "key_data_offset") {
            if (!c.ParseSize(spec.key_data_offset)) return false;
        } else if (!c.SkipValue()) {
            return false;
        }

        if (c.Consume('}')) {
            return true;
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

struct RegistryConfig {
    bool has_msv_x64 = false;
    bool has_wdigest_x64 = false;
    bool has_kerberos_x64 = false;
    bool has_dpapi_x64 = false;
    bool has_lsa_secrets_x64 = false;

    std::vector<MsvTemplateSpec> msv_x64;
    std::vector<WdigestTemplateSpec> wdigest_x64;
    std::vector<KerberosTemplateSpec> kerberos_x64;
    std::vector<DpapiTemplateSpec> dpapi_x64;
    std::vector<LsaSecretsTemplateSpec> lsa_secrets_x64;
};

bool ParseRegistryConfig(const std::string& text, RegistryConfig& out) {
    JsonCursor c(text);
    if (!c.Expect('{')) {
        return false;
    }
    if (c.Consume('}')) {
        return c.ok() && c.end();
    }
    while (c.ok()) {
        std::string key;
        if (!c.ParseString(key) || !c.Expect(':')) {
            return false;
        }

        if (key == "msv_x64") {
            out.has_msv_x64 = true;
            if (!ParseArray(c, out.msv_x64, ParseMsvTemplate)) {
                return false;
            }
        } else if (key == "wdigest_x64") {
            out.has_wdigest_x64 = true;
            if (!ParseArray(c, out.wdigest_x64, ParseWdigestTemplate)) {
                return false;
            }
        } else if (key == "kerberos_x64") {
            out.has_kerberos_x64 = true;
            if (!ParseArray(c, out.kerberos_x64, ParseKerberosTemplate)) {
                return false;
            }
        } else if (key == "dpapi_x64") {
            out.has_dpapi_x64 = true;
            if (!ParseArray(c, out.dpapi_x64, ParseDpapiTemplate)) {
                return false;
            }
        } else if (key == "lsa_secrets_x64") {
            out.has_lsa_secrets_x64 = true;
            if (!ParseArray(c, out.lsa_secrets_x64, ParseLsaSecretsTemplate)) {
                return false;
            }
        } else if (!c.SkipValue()) {
            return false;
        }

        if (c.Consume('}')) {
            return c.ok() && c.end();
        }
        if (!c.Expect(',')) {
            return false;
        }
    }
    return false;
}

template<typename TSpec>
bool ValidateBuildRanges(const std::vector<TSpec>& specs) {
    for (const auto& spec : specs) {
        if (spec.min_build > spec.max_build) {
            return false;
        }
    }
    return true;
}

bool ValidateMsvSpecs(const std::vector<MsvTemplateSpec>& specs) {
    if (!ValidateBuildRanges(specs)) {
        return false;
    }
    for (const auto& spec : specs) {
        if (spec.signature.empty()) {
            return false;
        }
        if (spec.parser_support) {
            if (spec.session_luid_offset == 0 || spec.session_credentials_ptr_offset == 0) {
                return false;
            }
        }
    }
    return true;
}

bool ValidateWdigestSpecs(const std::vector<WdigestTemplateSpec>& specs) {
    if (!ValidateBuildRanges(specs)) {
        return false;
    }
    for (const auto& spec : specs) {
        if (spec.signature.empty()) {
            return false;
        }
    }
    return true;
}

bool ValidateKerberosSpecs(const std::vector<KerberosTemplateSpec>& specs) {
    if (!ValidateBuildRanges(specs)) {
        return false;
    }
    for (const auto& spec : specs) {
        if (spec.signature.empty()) {
            return false;
        }
        if (spec.ticket_list_offsets.empty() || spec.session_luid_fallback_offsets.empty()) {
            return false;
        }
        if (spec.session_luid_offset == 0 ||
            spec.session_username_offset == 0 ||
            spec.session_domain_offset == 0 ||
            spec.session_password_ustr_offset == 0 ||
            spec.ticket_service_name_offset == 0 ||
            spec.ticket_target_name_offset == 0 ||
            spec.ticket_client_name_offset == 0 ||
            spec.ticket_flags_offset == 0 ||
            spec.ticket_key_type_offset == 0 ||
            spec.ticket_enc_type_offset == 0 ||
            spec.ticket_kvno_offset == 0 ||
            spec.ticket_buffer_len_offset == 0 ||
            spec.ticket_buffer_ptr_offset == 0 ||
            spec.external_name_first_string_offset == 0) {
            return false;
        }
    }
    return true;
}

bool ValidateDpapiSpecs(const std::vector<DpapiTemplateSpec>& specs) {
    if (!ValidateBuildRanges(specs)) {
        return false;
    }
    for (const auto& spec : specs) {
        if (spec.signature.empty()) {
            return false;
        }
    }
    return true;
}

bool ValidateLsaSecretsSpecs(const std::vector<LsaSecretsTemplateSpec>& specs) {
    if (!ValidateBuildRanges(specs)) {
        return false;
    }
    for (const auto& spec : specs) {
        if (spec.signature.empty()) {
            return false;
        }
        if (spec.iv_length == 0 || spec.offset_to_iv_ptr == 0 || spec.offset_to_aes_key_ptr == 0) {
            return false;
        }
        if (spec.handle_ptr_key_offset == 0 || spec.key_cb_secret_offset == 0 || spec.key_data_offset == 0) {
            return false;
        }
    }
    return true;
}

} // namespace

bool InitializeRegistry(const std::wstring& json_path) {
    constexpr std::streamoff kMaxJsonSize = static_cast<std::streamoff>(4 * 1024 * 1024);

    g_RegistryInitError.clear();
    g_MsvX64Templates.clear();
    g_WdigestX64Templates.clear();
    g_KerberosX64Templates.clear();
    g_DpapiX64Templates.clear();
    g_LsaSecretsX64Templates.clear();

    std::ifstream file(json_path);
    if (!file.is_open()) {
        g_RegistryInitError = L"Missing template file: " + json_path;
        return false;
    }

    file.seekg(0, std::ios::end);
    const std::streamoff file_size = file.tellg();
    if (file_size < 0) {
        g_RegistryInitError = L"Cannot determine template file size.";
        return false;
    }
    if (file_size > kMaxJsonSize) {
        g_RegistryInitError = L"Template file exceeds size limit (4 MB).";
        return false;
    }
    file.seekg(0, std::ios::beg);

    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    RegistryConfig cfg;
    if (!ParseRegistryConfig(text, cfg)) {
        g_RegistryInitError = L"Invalid template JSON format: " + json_path;
        return false;
    }

    if (!cfg.has_msv_x64 || cfg.msv_x64.empty()) {
        g_RegistryInitError = L"Missing or empty required section: msv_x64";
        return false;
    }
    if (!cfg.has_wdigest_x64 || cfg.wdigest_x64.empty()) {
        g_RegistryInitError = L"Missing or empty required section: wdigest_x64";
        return false;
    }
    if (!cfg.has_kerberos_x64 || cfg.kerberos_x64.empty()) {
        g_RegistryInitError = L"Missing or empty required section: kerberos_x64";
        return false;
    }
    if (!cfg.has_dpapi_x64 || cfg.dpapi_x64.empty()) {
        g_RegistryInitError = L"Missing or empty required section: dpapi_x64";
        return false;
    }
    if (!cfg.has_lsa_secrets_x64 || cfg.lsa_secrets_x64.empty()) {
        g_RegistryInitError = L"Missing or empty required section: lsa_secrets_x64";
        return false;
    }
    if (!ValidateMsvSpecs(cfg.msv_x64)) {
        g_RegistryInitError = L"Invalid msv_x64 template values.";
        return false;
    }
    if (!ValidateWdigestSpecs(cfg.wdigest_x64)) {
        g_RegistryInitError = L"Invalid wdigest_x64 template values.";
        return false;
    }
    if (!ValidateKerberosSpecs(cfg.kerberos_x64)) {
        g_RegistryInitError = L"Invalid kerberos_x64 template values.";
        return false;
    }
    if (!ValidateDpapiSpecs(cfg.dpapi_x64)) {
        g_RegistryInitError = L"Invalid dpapi_x64 template values.";
        return false;
    }
    if (!ValidateLsaSecretsSpecs(cfg.lsa_secrets_x64)) {
        g_RegistryInitError = L"Invalid lsa_secrets_x64 template values.";
        return false;
    }

    g_MsvX64Templates = std::move(cfg.msv_x64);
    g_WdigestX64Templates = std::move(cfg.wdigest_x64);
    g_KerberosX64Templates = std::move(cfg.kerberos_x64);
    g_DpapiX64Templates = std::move(cfg.dpapi_x64);
    g_LsaSecretsX64Templates = std::move(cfg.lsa_secrets_x64);
    return true;
}

const wchar_t* GetRegistryInitError() {
    return g_RegistryInitError.c_str();
}

const MsvTemplateSpec* SelectMsvTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(g_MsvX64Templates, build_number);
}

const WdigestTemplateSpec* SelectWdigestTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(g_WdigestX64Templates, build_number);
}

const KerberosTemplateSpec* SelectKerberosTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(g_KerberosX64Templates, build_number);
}

const DpapiTemplateSpec* SelectDpapiTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(g_DpapiX64Templates, build_number);
}

const LsaSecretsTemplateSpec* SelectLsaSecretsTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(g_LsaSecretsX64Templates, build_number);
}

} // namespace KvcForensic::lsa::templates
