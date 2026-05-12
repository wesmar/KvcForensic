#include "lsa/template_registry.h"

#include "core/text_utils.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>

namespace kvc::lsa::templates {

namespace {

constexpr std::uint32_t kBuildMax = std::numeric_limits<std::uint32_t>::max();

class JsonCursor {
public:
    explicit JsonCursor(const std::string& text) : text_(text) {}

    bool ok() const { return ok_; }
    bool end() { skip_ws(); return pos_ >= text_.size(); }

    bool consume(char ch) {
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == ch) { ++pos_; return true; }
        return false;
    }

    bool expect(char ch) {
        if (!consume(ch)) { ok_ = false; return false; }
        return true;
    }

    bool parse_string(std::string& out) {
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != '"') { ok_ = false; return false; }
        ++pos_;
        out.clear();
        while (pos_ < text_.size()) {
            const char ch = text_[pos_++];
            if (ch == '"') return true;
            if (ch == '\\') {
                if (pos_ >= text_.size()) { ok_ = false; return false; }
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
                    if (pos_ + 4 > text_.size()) { ok_ = false; return false; }
                    pos_ += 4;
                    out.push_back('?');
                    break;
                default: ok_ = false; return false;
                }
                continue;
            }
            out.push_back(ch);
        }
        ok_ = false;
        return false;
    }

    bool parse_bool(bool& out) {
        skip_ws();
        if (match_literal("true")) { out = true; return true; }
        if (match_literal("false")) { out = false; return true; }
        ok_ = false; return false;
    }

    bool parse_int(int& out) {
        std::int64_t v = 0;
        if (!parse_signed(v)) return false;
        if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) {
            ok_ = false; return false;
        }
        out = static_cast<int>(v);
        return true;
    }

    bool parse_uint32(std::uint32_t& out) {
        std::uint64_t v = 0;
        if (!parse_unsigned(v)) return false;
        if (v > std::numeric_limits<std::uint32_t>::max()) { ok_ = false; return false; }
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    bool parse_size(std::size_t& out) {
        std::uint64_t v = 0;
        if (!parse_unsigned(v)) return false;
        if (v > std::numeric_limits<std::size_t>::max()) { ok_ = false; return false; }
        out = static_cast<std::size_t>(v);
        return true;
    }

    bool skip_value() {
        skip_ws();
        if (pos_ >= text_.size()) { ok_ = false; return false; }
        const char ch = text_[pos_];
        if (ch == '{') return skip_object();
        if (ch == '[') return skip_array();
        if (ch == '"') { std::string t; return parse_string(t); }
        if (ch == 't' || ch == 'f') { bool t = false; return parse_bool(t); }
        if (ch == 'n') return match_literal("null");
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch))) return skip_number();
        ok_ = false; return false;
    }

private:
    void skip_ws() {
        while (pos_ < text_.size() &&
               std::isspace(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
    }

    bool match_literal(const char* literal) {
        const std::size_t len = std::strlen(literal);
        if (pos_ + len > text_.size()) return false;
        if (text_.compare(pos_, len, literal) == 0) { pos_ += len; return true; }
        return false;
    }

    bool parse_signed(std::int64_t& out) {
        skip_ws();
        const std::size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-') ++pos_;
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ok_ = false; return false;
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        const auto* begin = text_.data() + start;
        const auto* end = text_.data() + pos_;
        std::int64_t v = 0;
        const auto [p, ec] = std::from_chars(begin, end, v);
        if (ec != std::errc() || p != end) { ok_ = false; return false; }
        out = v;
        return true;
    }

    bool parse_unsigned(std::uint64_t& out) {
        skip_ws();
        const std::size_t start = pos_;
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ok_ = false; return false;
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        const auto* begin = text_.data() + start;
        const auto* end = text_.data() + pos_;
        std::uint64_t v = 0;
        const auto [p, ec] = std::from_chars(begin, end, v);
        if (ec != std::errc() || p != end) { ok_ = false; return false; }
        out = v;
        return true;
    }

    bool skip_number() {
        skip_ws();
        const std::size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-') ++pos_;
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ok_ = false; return false;
        }
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ok_ = false; return false;
        }
        return pos_ > start;
    }

    bool skip_object() {
        if (!expect('{')) return false;
        if (consume('}')) return true;
        while (ok_) {
            std::string k;
            if (!parse_string(k) || !expect(':') || !skip_value()) return false;
            if (consume('}')) return true;
            if (!expect(',')) return false;
        }
        return false;
    }

    bool skip_array() {
        if (!expect('[')) return false;
        if (consume(']')) return true;
        while (ok_) {
            if (!skip_value()) return false;
            if (consume(']')) return true;
            if (!expect(',')) return false;
        }
        return false;
    }

    const std::string& text_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

template <typename TItem, typename Parser>
bool parse_array(JsonCursor& c, std::vector<TItem>& out, Parser parse_one) {
    if (!c.expect('[')) return false;
    out.clear();
    if (c.consume(']')) return true;
    while (c.ok()) {
        TItem it{};
        if (!parse_one(c, it)) return false;
        out.push_back(std::move(it));
        if (c.consume(']')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_size_array(JsonCursor& c, std::vector<std::size_t>& out) {
    if (!c.expect('[')) return false;
    out.clear();
    if (c.consume(']')) return true;
    while (c.ok()) {
        std::size_t v = 0;
        if (!c.parse_size(v)) return false;
        out.push_back(v);
        if (c.consume(']')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_msv(JsonCursor& c, MsvTemplateSpec& s) {
    s.max_build = kBuildMax;
    if (!c.expect('{')) return false;
    if (c.consume('}')) return true;
    while (c.ok()) {
        std::string k;
        if (!c.parse_string(k) || !c.expect(':')) return false;
        if (k == "name") { if (!c.parse_string(s.name)) return false; }
        else if (k == "min_build") { if (!c.parse_uint32(s.min_build)) return false; }
        else if (k == "max_build") { if (!c.parse_uint32(s.max_build)) return false; }
        else if (k == "signature") { std::string v; if (!c.parse_string(v)) return false; s.signature = core::parse_hex(v); }
        else if (k == "first_entry_offset") { if (!c.parse_int(s.first_entry_offset)) return false; }
        else if (k == "offset2") { if (!c.parse_int(s.offset2)) return false; }
        else if (k == "first_entry_offset_correction") { if (!c.parse_int(s.first_entry_offset_correction)) return false; }
        else if (k == "session_luid_offset") { if (!c.parse_size(s.session_luid_offset)) return false; }
        else if (k == "session_username_offset") { if (!c.parse_size(s.session_username_offset)) return false; }
        else if (k == "session_domain_offset") { if (!c.parse_size(s.session_domain_offset)) return false; }
        else if (k == "session_sid_ptr_offset") { if (!c.parse_size(s.session_sid_ptr_offset)) return false; }
        else if (k == "session_credentials_ptr_offset") { if (!c.parse_size(s.session_credentials_ptr_offset)) return false; }
        else if (k == "session_credman_ptr_offset") { if (!c.parse_size(s.session_credman_ptr_offset)) return false; }
        else if (k == "parser_support") { if (!c.parse_bool(s.parser_support)) return false; }
        else if (!c.skip_value()) return false;
        if (c.consume('}')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_wdigest(JsonCursor& c, WdigestTemplateSpec& s) {
    s.max_build = kBuildMax;
    if (!c.expect('{')) return false;
    if (c.consume('}')) return true;
    while (c.ok()) {
        std::string k;
        if (!c.parse_string(k) || !c.expect(':')) return false;
        if (k == "name") { if (!c.parse_string(s.name)) return false; }
        else if (k == "min_build") { if (!c.parse_uint32(s.min_build)) return false; }
        else if (k == "max_build") { if (!c.parse_uint32(s.max_build)) return false; }
        else if (k == "signature") { std::string v; if (!c.parse_string(v)) return false; s.signature = core::parse_hex(v); }
        else if (k == "first_entry_offset") { if (!c.parse_int(s.first_entry_offset)) return false; }
        else if (k == "primary_offset") { if (!c.parse_size(s.primary_offset)) return false; }
        else if (!c.skip_value()) return false;
        if (c.consume('}')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_kerberos(JsonCursor& c, KerberosTemplateSpec& s) {
    s.max_build = kBuildMax;
    if (!c.expect('{')) return false;
    if (c.consume('}')) return true;
    while (c.ok()) {
        std::string k;
        if (!c.parse_string(k) || !c.expect(':')) return false;
        if (k == "name") { if (!c.parse_string(s.name)) return false; }
        else if (k == "min_build") { if (!c.parse_uint32(s.min_build)) return false; }
        else if (k == "max_build") { if (!c.parse_uint32(s.max_build)) return false; }
        else if (k == "signature") { std::string v; if (!c.parse_string(v)) return false; s.signature = core::parse_hex(v); }
        else if (k == "first_entry_offset") { if (!c.parse_int(s.first_entry_offset)) return false; }
        else if (k == "session_luid_offset") { if (!c.parse_size(s.session_luid_offset)) return false; }
        else if (k == "session_username_offset") { if (!c.parse_size(s.session_username_offset)) return false; }
        else if (k == "session_domain_offset") { if (!c.parse_size(s.session_domain_offset)) return false; }
        else if (k == "session_password_ustr_offset") { if (!c.parse_size(s.session_password_ustr_offset)) return false; }
        else if (k == "session_luid_fallback_offsets") { if (!parse_size_array(c, s.session_luid_fallback_offsets)) return false; }
        else if (k == "ticket_list_offsets") { if (!parse_size_array(c, s.ticket_list_offsets)) return false; }
        else if (k == "ticket_service_name_offset") { if (!c.parse_size(s.ticket_service_name_offset)) return false; }
        else if (k == "ticket_target_name_offset") { if (!c.parse_size(s.ticket_target_name_offset)) return false; }
        else if (k == "ticket_client_name_offset") { if (!c.parse_size(s.ticket_client_name_offset)) return false; }
        else if (k == "ticket_flags_offset") { if (!c.parse_size(s.ticket_flags_offset)) return false; }
        else if (k == "ticket_key_type_offset") { if (!c.parse_size(s.ticket_key_type_offset)) return false; }
        else if (k == "ticket_enc_type_offset") { if (!c.parse_size(s.ticket_enc_type_offset)) return false; }
        else if (k == "ticket_kvno_offset") { if (!c.parse_size(s.ticket_kvno_offset)) return false; }
        else if (k == "ticket_buffer_len_offset") { if (!c.parse_size(s.ticket_buffer_len_offset)) return false; }
        else if (k == "ticket_buffer_ptr_offset") { if (!c.parse_size(s.ticket_buffer_ptr_offset)) return false; }
        else if (k == "external_name_first_string_offset") { if (!c.parse_size(s.external_name_first_string_offset)) return false; }
        else if (!c.skip_value()) return false;
        if (c.consume('}')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_dpapi(JsonCursor& c, DpapiTemplateSpec& s) {
    s.max_build = kBuildMax;
    if (!c.expect('{')) return false;
    if (c.consume('}')) return true;
    while (c.ok()) {
        std::string k;
        if (!c.parse_string(k) || !c.expect(':')) return false;
        if (k == "name") { if (!c.parse_string(s.name)) return false; }
        else if (k == "min_build") { if (!c.parse_uint32(s.min_build)) return false; }
        else if (k == "max_build") { if (!c.parse_uint32(s.max_build)) return false; }
        else if (k == "signature") { std::string v; if (!c.parse_string(v)) return false; s.signature = core::parse_hex(v); }
        else if (k == "first_entry_offset") { if (!c.parse_int(s.first_entry_offset)) return false; }
        else if (!c.skip_value()) return false;
        if (c.consume('}')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_tspkg(JsonCursor& c, TspkgTemplateSpec& s) {
    s.max_build = kBuildMax;
    s.luid_offset = 16;
    s.primary_offset = 24;
    s.blob_header_skip = 0;
    if (!c.expect('{')) return false;
    if (c.consume('}')) return true;
    while (c.ok()) {
        std::string k;
        if (!c.parse_string(k) || !c.expect(':')) return false;
        if (k == "name") { if (!c.parse_string(s.name)) return false; }
        else if (k == "min_build") { if (!c.parse_uint32(s.min_build)) return false; }
        else if (k == "max_build") { if (!c.parse_uint32(s.max_build)) return false; }
        else if (k == "signature") { std::string v; if (!c.parse_string(v)) return false; s.signature = core::parse_hex(v); }
        else if (k == "first_entry_offset") { if (!c.parse_int(s.first_entry_offset)) return false; }
        else if (k == "luid_offset") { if (!c.parse_size(s.luid_offset)) return false; }
        else if (k == "primary_offset") { if (!c.parse_size(s.primary_offset)) return false; }
        else if (k == "blob_header_skip") { if (!c.parse_size(s.blob_header_skip)) return false; }
        else if (!c.skip_value()) return false;
        if (c.consume('}')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

bool parse_lsa_secrets(JsonCursor& c, LsaSecretsTemplateSpec& s) {
    s.max_build = kBuildMax;
    if (!c.expect('{')) return false;
    if (c.consume('}')) return true;
    while (c.ok()) {
        std::string k;
        if (!c.parse_string(k) || !c.expect(':')) return false;
        if (k == "name") { if (!c.parse_string(s.name)) return false; }
        else if (k == "min_build") { if (!c.parse_uint32(s.min_build)) return false; }
        else if (k == "max_build") { if (!c.parse_uint32(s.max_build)) return false; }
        else if (k == "signature") { std::string v; if (!c.parse_string(v)) return false; s.signature = core::parse_hex(v); }
        else if (k == "offset_to_iv_ptr") { if (!c.parse_int(s.offset_to_iv_ptr)) return false; }
        else if (k == "offset_to_aes_key_ptr") { if (!c.parse_int(s.offset_to_aes_key_ptr)) return false; }
        else if (k == "offset_to_des_key_ptr") { if (!c.parse_int(s.offset_to_des_key_ptr)) return false; }
        else if (k == "iv_length") { if (!c.parse_size(s.iv_length)) return false; }
        else if (k == "handle_ptr_key_offset") { if (!c.parse_size(s.handle_ptr_key_offset)) return false; }
        else if (k == "key_cb_secret_offset") { if (!c.parse_size(s.key_cb_secret_offset)) return false; }
        else if (k == "key_data_offset") { if (!c.parse_size(s.key_data_offset)) return false; }
        else if (!c.skip_value()) return false;
        if (c.consume('}')) return true;
        if (!c.expect(',')) return false;
    }
    return false;
}

template <typename Spec>
const Spec* select_by_build(const std::vector<Spec>& v, std::uint32_t build) {
    for (const auto& s : v) {
        if (build >= s.min_build && build <= s.max_build) return &s;
    }
    return nullptr;
}

template <typename Spec>
std::vector<const Spec*> select_all_by_build(const std::vector<Spec>& v, std::uint32_t build) {
    std::vector<const Spec*> out;
    for (const auto& s : v) {
        if (build >= s.min_build && build <= s.max_build) out.push_back(&s);
    }
    return out;
}

} // namespace

bool TemplateRegistry::load(const std::filesystem::path& json_path) {
    constexpr std::streamoff kMaxJsonSize = static_cast<std::streamoff>(4 * 1024 * 1024);

    error_.clear();
    msv_.clear(); wdigest_.clear(); kerberos_.clear();
    dpapi_.clear(); lsa_secrets_.clear(); tspkg_.clear();

    std::ifstream f(json_path, std::ios::binary);
    if (!f.is_open()) {
        error_ = "missing template file: " + json_path.string();
        return false;
    }
    f.seekg(0, std::ios::end);
    const std::streamoff sz = f.tellg();
    if (sz < 0) { error_ = "cannot stat template file"; return false; }
    if (sz > kMaxJsonSize) { error_ = "template file exceeds 4 MB"; return false; }
    f.seekg(0, std::ios::beg);
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    JsonCursor c(text);
    if (!c.expect('{')) { error_ = "invalid root"; return false; }
    bool has_msv = false, has_wdg = false, has_krb = false,
         has_dpa = false, has_sec = false;
    bool has_tspkg = false;
    if (!c.consume('}')) {
        while (c.ok()) {
            std::string k;
            if (!c.parse_string(k) || !c.expect(':')) { error_ = "expected key:"; return false; }
            if (k == "msv_x64") { has_msv = true; if (!parse_array(c, msv_, parse_msv)) { error_ = "invalid msv_x64"; return false; } }
            else if (k == "wdigest_x64") { has_wdg = true; if (!parse_array(c, wdigest_, parse_wdigest)) { error_ = "invalid wdigest_x64"; return false; } }
            else if (k == "kerberos_x64") { has_krb = true; if (!parse_array(c, kerberos_, parse_kerberos)) { error_ = "invalid kerberos_x64"; return false; } }
            else if (k == "dpapi_x64") { has_dpa = true; if (!parse_array(c, dpapi_, parse_dpapi)) { error_ = "invalid dpapi_x64"; return false; } }
            else if (k == "lsa_secrets_x64") { has_sec = true; if (!parse_array(c, lsa_secrets_, parse_lsa_secrets)) { error_ = "invalid lsa_secrets_x64"; return false; } }
            else if (k == "tspkg_x64") { has_tspkg = true; if (!parse_array(c, tspkg_, parse_tspkg)) { error_ = "invalid tspkg_x64"; return false; } }
            else if (!c.skip_value()) { error_ = "value parse failed"; return false; }
            if (c.consume('}')) break;
            if (!c.expect(',')) { error_ = "expected ','"; return false; }
        }
    }

    if (!has_msv || msv_.empty()) { error_ = "missing msv_x64"; return false; }
    if (!has_wdg || wdigest_.empty()) { error_ = "missing wdigest_x64"; return false; }
    if (!has_krb || kerberos_.empty()) { error_ = "missing kerberos_x64"; return false; }
    if (!has_dpa || dpapi_.empty()) { error_ = "missing dpapi_x64"; return false; }
    if (!has_sec || lsa_secrets_.empty()) { error_ = "missing lsa_secrets_x64"; return false; }
    (void)has_tspkg;

    // Light validation: signature non-empty for every spec.
    auto check_sig = [&](const auto& vec, const char* what) {
        for (const auto& s : vec) {
            if (s.signature.empty()) { error_ = std::string("empty signature in ") + what + " (" + s.name + ")"; return false; }
        }
        return true;
    };
    if (!check_sig(msv_, "msv_x64") ||
        !check_sig(wdigest_, "wdigest_x64") ||
        !check_sig(kerberos_, "kerberos_x64") ||
        !check_sig(dpapi_, "dpapi_x64") ||
        !check_sig(lsa_secrets_, "lsa_secrets_x64") ||
        !check_sig(tspkg_, "tspkg_x64")) {
        return false;
    }
    return true;
}

const MsvTemplateSpec* TemplateRegistry::select_msv(std::uint32_t b) const { return select_by_build(msv_, b); }
std::vector<const MsvTemplateSpec*> TemplateRegistry::select_msv_candidates(std::uint32_t b) const { return select_all_by_build(msv_, b); }
const WdigestTemplateSpec* TemplateRegistry::select_wdigest(std::uint32_t b) const { return select_by_build(wdigest_, b); }
const KerberosTemplateSpec* TemplateRegistry::select_kerberos(std::uint32_t b) const { return select_by_build(kerberos_, b); }
const DpapiTemplateSpec* TemplateRegistry::select_dpapi(std::uint32_t b) const { return select_by_build(dpapi_, b); }
const LsaSecretsTemplateSpec* TemplateRegistry::select_lsa_secrets(std::uint32_t b) const { return select_by_build(lsa_secrets_, b); }
std::vector<const LsaSecretsTemplateSpec*> TemplateRegistry::select_lsa_secrets_candidates(std::uint32_t b) const { return select_all_by_build(lsa_secrets_, b); }
const TspkgTemplateSpec* TemplateRegistry::select_tspkg(std::uint32_t b) const { return select_by_build(tspkg_, b); }

} // namespace kvc::lsa::templates
