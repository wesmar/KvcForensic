#include "security/MsvCredentials.h"

#include "core/HexUtils.h"
#include "core/TextEncoding.h"

#include <iomanip>
#include <string>
#include <sstream>

namespace KvcForensic::security {

std::wstring MsvCredential::to_wstring() const {
    std::wstringstream ss;
    
    if (!username.empty()) {
        ss << L"Username: " << username << L"\n";
    }
    if (!domainname.empty()) {
        ss << L"Domain: " << domainname << L"\n";
    }
    
    if (!nt_hash.empty()) {
        ss << L"NT: " << core::BytesToHex(nt_hash) << L"\n";
    }
    
    if (!lm_hash.empty()) {
        ss << L"LM: " << core::BytesToHex(lm_hash) << L"\n";
    }
    
    if (!sha1_hash.empty()) {
        ss << L"SHA1: " << core::BytesToHex(sha1_hash) << L"\n";
    }
    
    if (!dpapi.empty()) {
        ss << L"DPAPI: " << core::BytesToHex(dpapi) << L"\n";
    }
    
    if (is_iso_protected) {
        ss << L"[ISO Protected]\n";
    }
    
    return ss.str();
}

std::wstring CredmanCredential::to_wstring() const {
    std::wstringstream ss;
    if (!username.empty()) ss << L"Username: " << username << L"\n";
    if (!domainname.empty()) ss << L"Domain: " << domainname << L"\n";
    if (!password.empty()) ss << L"Password: " << password << L"\n";
    if (password.empty() && !password_hex.empty()) ss << L"password (hex): " << password_hex << L"\n";
    return ss.str();
}

std::wstring WdigestCredential::to_wstring() const {
    std::wstringstream ss;
    if (!username.empty()) ss << L"Username: " << username << L"\n";
    if (!domainname.empty()) ss << L"Domain: " << domainname << L"\n";
    if (!password.empty()) ss << L"Password: " << password << L"\n";
    if (password.empty() && !password_hex.empty()) ss << L"password (hex): " << password_hex << L"\n";
    return ss.str();
}

std::wstring KerberosCredential::to_wstring() const {
    std::wstringstream ss;
    if (!username.empty()) ss << L"Username: " << username << L"\n";
    if (!domainname.empty()) ss << L"Domain: " << domainname << L"\n";
    if (!password.empty()) ss << L"Password: " << password << L"\n";
    if (password.empty() && !password_hex.empty()) ss << L"password (hex): " << password_hex << L"\n";
    for (const auto& t : tickets) {
        if (!t.service_name.empty()) ss << L"  ServiceName: " << t.service_name << L"\n";
        if (!t.target_name.empty())  ss << L"  TargetName:  " << t.target_name  << L"\n";
        if (!t.client_name.empty())  ss << L"  ClientName:  " << t.client_name  << L"\n";
        ss << L"  Flags: 0x" << std::hex << std::setfill(L'0') << std::setw(8) << t.flags << std::dec << L"\n";
        ss << L"  EncType: " << t.enc_type << L"  Kvno: " << t.kvno << L"\n";
        if (!t.data.empty())
            ss << L"  Ticket: " << core::BytesToHex(t.data).substr(0, 64) << L"...\n";
    }
    return ss.str();
}

std::wstring DpapiCredential::to_wstring() const {
    std::wstringstream ss;
    ss << L"luid " << luid << L"\n";
    ss << L"key_guid " << core::Utf8ToWide(key_guid) << L"\n";
    
    ss << L"masterkey " << core::BytesToHex(masterkey) << L"\n";
    
    ss << L"sha1_masterkey " << core::Utf8ToWide(sha1_masterkey) << L"\n";
    return ss.str();
}

} // namespace KvcForensic::security
