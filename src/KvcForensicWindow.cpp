#include "KvcForensicWindow.h"
#include "Resource.h"

#include "analysis/SafeAnalysisReport.h"
#include "core/HexUtils.h"
#include "core/StringUtils.h"
#include "core/TextEncoding.h"
#include "security/MsvCredentials.h"

#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

namespace KvcForensic::ui {

// ---------------------------------------------------------------------------
// Constants (logical DIPs at 96 DPI; scaled via fonts_.S())
// ---------------------------------------------------------------------------
constexpr wchar_t kWndClass[]     = L"KvcForensicMainWnd";
constexpr int     kMenuBarDip     = 34;
constexpr int     kStatusBarDip   = 28;
constexpr int     kOuterPadDip    = 8;
constexpr int     kSplitterDip    = 8;
constexpr int     kSplitterMinDip = 160;
constexpr wchar_t kSettingsKey[]  = L"Software\\KVC\\KvcForensic";
constexpr wchar_t kWindowPlacementValue[] = L"WindowPlacement";
constexpr wchar_t kSplitterDipValue[] = L"SplitterDip";

// Status bar parts
constexpr int SB_FILE  = 0;
constexpr int SB_BUILD = 1;
constexpr int SB_STATE = 2;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
namespace {

bool AppUseDarkMode() {
    HKEY hk;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        0, KEY_READ, &hk) != ERROR_SUCCESS) return false;
    DWORD val = 1, sz = sizeof(val);
    ::RegQueryValueExW(hk, L"AppsUseLightTheme", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(&val), &sz);
    ::RegCloseKey(hk);
    return val == 0;
}

void SetUxThemePreferredAppMode(bool dark) {
    if (HMODULE ux = ::GetModuleHandleW(L"uxtheme.dll")) {
        using FnSetPreferredAppMode = int(WINAPI*)(int);
        using FnFlushMenuThemes = void(WINAPI*)();
        if (auto fn = reinterpret_cast<FnSetPreferredAppMode>(::GetProcAddress(ux, MAKEINTRESOURCEA(135)))) {
            // 2 = ForceDark, 3 = ForceLight (keeps scrollbars synced with AppsUseLightTheme)
            fn(dark ? 2 : 3);
        }
        if (auto flush = reinterpret_cast<FnFlushMenuThemes>(::GetProcAddress(ux, MAKEINTRESOURCEA(136)))) {
            flush();
        }
    }
}

// Extract filename from full path (no filesystem dependency)
std::wstring FileName(const std::wstring& path) {
    auto p = path.rfind(L'\\');
    if (p == std::wstring::npos) p = path.rfind(L'/');
    return (p == std::wstring::npos) ? path : path.substr(p + 1);
}

// Convert narrow ASCII string to wstring (for SID display)
std::wstring ToWide(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}


bool StartsWithI(const std::wstring& text, const wchar_t* prefix) {
    const std::size_t n = std::wcslen(prefix);
    return text.size() >= n && _wcsnicmp(text.c_str(), prefix, n) == 0;
}

bool EndsWithI(const std::wstring& text, const wchar_t* suffix) {
    const std::size_t n = std::wcslen(suffix);
    return text.size() >= n &&
        _wcsicmp(text.c_str() + (text.size() - n), suffix) == 0;
}

bool ContainsI(const std::wstring& text, const wchar_t* needle) {
    return core::ContainsInsensitive(text, needle);
}

bool IsSystemLikePrincipal(const std::wstring& user, const std::wstring& domain) {
    if (user.empty()) return true;
    if (StartsWithI(user, L"DWM-") || StartsWithI(user, L"UMFD-")) return true;
    if (EndsWithI(user, L"$")) return true;
    if (ContainsI(user, L"local service") || ContainsI(user, L"network service") || ContainsI(user, L"system")) {
        return true;
    }
    if (ContainsI(domain, L"window manager") || ContainsI(domain, L"font driver")) {
        return true;
    }
    return false;
}

bool IsUserLikePrincipal(const std::wstring& user, const std::wstring& domain) {
    return !user.empty() && !IsSystemLikePrincipal(user, domain);
}

enum class SessionClass {
    User,
    Virtual,
    Machine,
    System
};

bool HasUserLikeCredentialIdentity(const lsa::LogonSession& s) {
    for (const auto& c : s.msv_credentials) {
        if (IsUserLikePrincipal(c.username, c.domainname)) return true;
    }
    for (const auto& c : s.credman_credentials) {
        if (IsUserLikePrincipal(c.username, c.domainname)) return true;
    }
    for (const auto& c : s.wdigest_credentials) {
        if (IsUserLikePrincipal(c.username, c.domainname)) return true;
    }
    for (const auto& c : s.kerberos_credentials) {
        if (IsUserLikePrincipal(c.username, c.domainname)) return true;
    }
    return false;
}

SessionClass ClassifySession(const lsa::LogonSession& s) {
    const bool sid_virtual = s.sid.rfind("S-1-5-83-", 0) == 0;
    const bool sid_dwm = s.sid.rfind("S-1-5-90-", 0) == 0;
    const bool sid_umfd = s.sid.rfind("S-1-5-96-", 0) == 0;

    if (sid_virtual || ContainsI(s.domainname, L"virtual machine")) {
        return SessionClass::Virtual;
    }
    if (IsUserLikePrincipal(s.username, s.domainname) || HasUserLikeCredentialIdentity(s)) {
        return SessionClass::User;
    }
    if (StartsWithI(s.username, L"DWM-") ||
        StartsWithI(s.username, L"UMFD-") ||
        sid_dwm || sid_umfd ||
        s.username.empty()) {
        return SessionClass::System;
    }
    if (EndsWithI(s.username, L"$") || s.sid == "S-1-5-18" || s.sid == "S-1-5-19" || s.sid == "S-1-5-20") {
        return SessionClass::Machine;
    }
    if (ContainsI(s.domainname, L"window manager") || ContainsI(s.domainname, L"font driver")) {
        return SessionClass::System;
    }
    return SessionClass::User;
}

bool HasInterestingSecrets(const lsa::LogonSession& s) {
    return !s.msv_credentials.empty() || !s.credman_credentials.empty()
        || !s.wdigest_credentials.empty() || !s.tspkg_credentials.empty()
        || !s.kerberos_credentials.empty() || !s.dpapi_credentials.empty();
}

bool ShouldShowSession(const lsa::LogonSession& s, bool show_all_accounts) {
    if (show_all_accounts) return true;

    const SessionClass cls = ClassifySession(s);
    if (cls == SessionClass::User || cls == SessionClass::Virtual) return true;
    if (cls == SessionClass::Machine) return HasInterestingSecrets(s) || HasUserLikeCredentialIdentity(s);
    return false;
}

const wchar_t* SessionTag(SessionClass cls) {
    switch (cls) {
    case SessionClass::User:    return L"USER";
    case SessionClass::Virtual: return L"VIRTUAL";
    case SessionClass::Machine: return L"MACHINE";
    case SessionClass::System:  return L"SYSTEM";
    default: return L"UNKNOWN";
    }
}

template <typename TKeyBuilder, typename TContainer>
std::size_t CountUniqueBy(const TContainer& items, TKeyBuilder key_builder) {
    std::set<std::wstring> seen;
    for (const auto& item : items) {
        seen.insert(key_builder(item));
    }
    return seen.size();
}

std::wstring BuildMsvKey(const security::MsvCredential& c) {
    return c.username + L"|" + c.domainname + L"|" +
           core::BytesToHex(c.nt_hash) + L"|" + core::BytesToHex(c.sha1_hash) + L"|" +
           core::BytesToHex(c.lm_hash) + L"|" + core::BytesToHex(c.dpapi) + L"|" +
           (c.is_iso_protected ? L"1" : L"0");
}

std::wstring BuildCredmanKey(const security::CredmanCredential& c) {
    return c.username + L"|" + c.domainname + L"|" + c.password + L"|" + c.password_hex;
}

std::wstring BuildWdigestKey(const security::WdigestCredential& c) {
    std::wstringstream ss;
    ss << c.luid << L"|"<< c.username << L"|" << c.domainname << L"|" << c.password << L"|" << c.password_hex;
    return ss.str();
}

std::wstring BuildKerberosKey(const security::KerberosCredential& c) {
    std::wstringstream ss;
    ss << c.luid << L"|"<< c.username << L"|" << c.domainname << L"|" << c.password << L"|" << c.password_hex;
    return ss.str();
}

std::wstring DecodeTicketFlags(std::uint32_t flags) {
    struct FlagDef { std::uint32_t mask; const wchar_t* name; };
    static const FlagDef kDefs[] = {
        { 0x40000000, L"forwardable" },
        { 0x20000000, L"forwarded" },
        { 0x10000000, L"proxiable" },
        { 0x08000000, L"proxy" },
        { 0x04000000, L"may_postdate" },
        { 0x02000000, L"postdated" },
        { 0x01000000, L"invalid" },
        { 0x00800000, L"renewable" },
        { 0x00400000, L"initial" },
        { 0x00200000, L"pre_authent" },
        { 0x00100000, L"hw_authent" },
        { 0x00040000, L"ok_as_delegate" },
        { 0x00010000, L"name_canonicalize" },
    };
    std::wstring result;
    for (const auto& d : kDefs) {
        if (flags & d.mask) {
            if (!result.empty()) result += L" | ";
            result += d.name;
        }
    }
    return result.empty() ? L"(none)" : result;
}

std::wstring EncTypeToString(std::uint32_t enc_type) {
    switch (enc_type) {
    case  3: return L"3  [DES-CBC-MD5]";
    case 17: return L"17  [AES128-CTS-HMAC-SHA1-96]";
    case 18: return L"18  [AES256-CTS-HMAC-SHA1-96]";
    case 23: return L"23  [RC4-HMAC]";
    default: {
        wchar_t tmp[32];
        swprintf_s(tmp, L"%u", enc_type);
        return tmp;
    }
    }
}

std::wstring BuildDpapiKey(const security::DpapiCredential& c) {
    std::wstringstream ss;
    ss << c.luid << L"|" << core::Utf8ToWide(c.key_guid) << L"|" << core::BytesToHex(c.masterkey) << L"|" << core::Utf8ToWide(c.sha1_masterkey);
    return ss.str();
}

template <typename TContainer, typename TKeyBuilder>
std::vector<std::size_t> BuildUniqueIndices(const TContainer& items, TKeyBuilder key_builder) {
    std::vector<std::size_t> out;
    std::set<std::wstring> seen;
    for (std::size_t i = 0; i < items.size(); ++i) {
        std::wstring key = key_builder(items[i]);
        if (seen.insert(key).second) out.push_back(i);
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Node encoding
// ---------------------------------------------------------------------------
LPARAM KvcForensicWindow::EncodeNode(NodeType type, int idx) {
    return (LPARAM)(((UINT32)type << 16) | (UINT32)(idx & 0xFFFF));
}
NodeType KvcForensicWindow::GetNodeType(LPARAM p) {
    return (NodeType)((UINT32)p >> 16);
}
int KvcForensicWindow::GetNodeIndex(LPARAM p) {
    return (int)((UINT32)p & 0xFFFF);
}

// ---------------------------------------------------------------------------
// Create / RunMessageLoop
// ---------------------------------------------------------------------------
bool KvcForensicWindow::Create(HINSTANCE instance, int nCmdShow) {
    ::SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES;
    ::InitCommonControlsEx(&icc);

    hInstance_ = instance;

    const UINT sys_dpi = ::GetDpiForSystem();
    const int icon_sm_sz = ::GetSystemMetricsForDpi(SM_CXSMICON, sys_dpi);
    icon_big_   = ::LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP_ICON));
    icon_small_ = reinterpret_cast<HICON>(::LoadImageW(instance,
        MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, icon_sm_sz, icon_sm_sz, LR_DEFAULTCOLOR));

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &KvcForensicWindow::WndProc;
    wc.hInstance     = instance;
    wc.hCursor       = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon         = icon_big_   ? icon_big_   : ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm       = icon_small_ ? icon_small_ : ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kWndClass;
    if (!::RegisterClassExW(&wc)) return false;

    const int init_w = ::MulDiv(1120, static_cast<int>(sys_dpi), 96);
    const int init_h = ::MulDiv(700, static_cast<int>(sys_dpi), 96);

    hwnd_ = ::CreateWindowExW(
        0, kWndClass, L"KvcForensic",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, init_w, init_h,
        nullptr, nullptr, instance, this);
    if (!hwnd_) return false;

    ::SendMessageW(hwnd_, WM_SETICON, ICON_BIG,   reinterpret_cast<LPARAM>(wc.hIcon));
    ::SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(wc.hIconSm));

    initial_show_cmd_ = nCmdShow;
    RestoreWindowState();
    UpdateTheme();
    ::ShowWindow(hwnd_, initial_show_cmd_);
    ::UpdateWindow(hwnd_);
    return true;
}

int KvcForensicWindow::RunMessageLoop() {
    MSG msg{};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!accel_ || !::TranslateAcceleratorW(hwnd_, accel_, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

// ---------------------------------------------------------------------------
// WndProc
// ---------------------------------------------------------------------------
LRESULT CALLBACK KvcForensicWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    KvcForensicWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<KvcForensicWindow*>(cs->lpCreateParams);
        self->hwnd_ = hwnd;  // set early so CreateControls can use hwnd_
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<KvcForensicWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    return self ? self->HandleMessage(hwnd, msg, wp, lp)
                : ::DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT KvcForensicWindow::HandleMessage(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {

    case WM_CREATE:
        CreateControls(hwnd);
        return 0;

    case WM_DPICHANGED: {
        const UINT new_dpi = HIWORD(wp);
        const UINT old_dpi = dpi_ ? dpi_ : 96;
        if (new_dpi != 0 && new_dpi != old_dpi) {
            splitter_x_ = ::MulDiv(splitter_x_, static_cast<int>(new_dpi), static_cast<int>(old_dpi));
            RecreateFonts(new_dpi);
            if (menu_bar_) menu_bar_->Remeasure();
            const MARGINS m{ fonts_.S(kOuterPadDip), fonts_.S(kOuterPadDip),
                             fonts_.S(kMenuBarDip),  fonts_.S(kStatusBarDip) };
            ApplyBackdrop(hwnd_, is_dark_mode_, m);
        }
        const auto* suggested = reinterpret_cast<const RECT*>(lp);
        if (suggested) {
            ::SetWindowPos(hwnd_, nullptr,
                suggested->left, suggested->top,
                suggested->right - suggested->left,
                suggested->bottom - suggested->top,
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        RECT rc{};
        ::GetClientRect(hwnd_, &rc);
        LayoutControls(rc.right, rc.bottom);
        ::InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
    }

    case WM_SIZE: {
        const int w = LOWORD(lp);
        const int h = HIWORD(lp);
        const int min_split = fonts_.S(kSplitterMinDip);
        splitter_x_ = std::clamp(splitter_x_, min_split, std::max(min_split, w - min_split));
        LayoutControls(w, h);
        ::InvalidateRect(hwnd_, nullptr, FALSE);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC hdc = ::BeginPaint(hwnd_, &ps);
        PaintWindow(hdc);
        ::EndPaint(hwnd_, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_MEASUREITEM: {
        auto* mis = reinterpret_cast<MEASUREITEMSTRUCT*>(lp);
        if (mis && mis->CtlType == ODT_MENU && menu_bar_) {
            menu_bar_->Measure(*mis);
            return TRUE;
        }
        break;
    }

    case WM_DRAWITEM: {
        const auto* dis = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
        if (dis && dis->CtlType == ODT_MENU && menu_bar_) {
            menu_bar_->Draw(*dis);
            return TRUE;
        }
        break;
    }

    case WM_SYSKEYDOWN:
        if (wp == VK_F10 && menu_bar_) {
            menu_bar_->Open(hwnd_, 0, true);
            return 0;
        }
        break;

    case WM_SYSCHAR:
        if (menu_bar_ && menu_bar_->OpenByMnemonic(hwnd_, static_cast<wchar_t>(wp))) {
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDM_FILE_OPEN:  OpenDumpDialog(); return 0;
        case IDM_FILE_EXIT:  ::DestroyWindow(hwnd_); return 0;
        case IDM_VIEW_ADVANCED: {
            show_all_accounts_ = !show_all_accounts_;
            if (view_menu_) {
                ::CheckMenuItem(view_menu_, IDM_VIEW_ADVANCED,
                    MF_BYCOMMAND | (show_all_accounts_ ? MF_CHECKED : MF_UNCHECKED));
            }
            if (has_report_) PopulateTree();
            return 0;
        }
        case IDM_EDIT_COPY:  CopySelectedRows(); return 0;
        case IDM_HELP_ABOUT:
            ::MessageBoxW(hwnd_,
                L"KvcForensic - LSASS minidump credential extractor\n"
                L"\n"
                L"Marek Weso\u0142owski - WESMAR\n"
                L"\u00A9 2026\n"
                L"marek@kvc.pl\n"
                L"WhatsApp: +48 607-440-283",
                L"About KvcForensic", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;

    case WM_NOTIFY: {
        auto* nm = reinterpret_cast<NMHDR*>(lp);
        if (nm->hwndFrom == tree_ && nm->code == TVN_SELCHANGEDW) {
            auto* ntv = reinterpret_cast<NMTREEVIEWW*>(lp);
            ShowNodeDetail(ntv->itemNew.lParam);
        }
        if (nm->hwndFrom == detail_ && nm->code == NM_CUSTOMDRAW) {
            return HandleListCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(lp));
        }
        if (nm->hwndFrom == detail_ && nm->code == NM_RCLICK && menu_bar_ && context_menu_) {
            POINT pt{};
            ::GetCursorPos(&pt);
            const int sel = ListView_GetSelectedCount(detail_);
            ::EnableMenuItem(context_menu_, IDM_EDIT_COPY,
                MF_BYCOMMAND | (sel > 0 ? MF_ENABLED : MF_GRAYED));
            menu_bar_->TrackContext(hwnd_, context_menu_, pt);
        }
        return 0;
    }

    case WM_LBUTTONDOWN: {
        const POINT pt{ static_cast<short>(LOWORD(lp)), static_cast<short>(HIWORD(lp)) };
        if (menu_bar_) {
            const int hit = menu_bar_->HitTest(pt);
            if (hit >= 0) {
                menu_bar_->Open(hwnd_, hit, false);
                return 0;
            }
        }
        const int split_w = fonts_.S(kSplitterDip);
        if (pt.x >= splitter_x_ && pt.x < splitter_x_ + split_w && pt.y >= fonts_.S(kMenuBarDip)) {
            splitter_drag_ = true;
            ::SetCapture(hwnd_);
            ::SetCursor(::LoadCursorW(nullptr, IDC_SIZEWE));
        }
        return 0;
    }

    case WM_MOUSEMOVE: {
        const POINT pt{ static_cast<short>(LOWORD(lp)), static_cast<short>(HIWORD(lp)) };
        if (!tracking_mouse_) {
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, hwnd_, 0 };
            ::TrackMouseEvent(&tme);
            tracking_mouse_ = true;
        }
        if (splitter_drag_) {
            RECT rc{};
            ::GetClientRect(hwnd_, &rc);
            const int min_split = fonts_.S(kSplitterMinDip);
            const int limit = rc.right - min_split;
            splitter_x_ = std::clamp(static_cast<int>(pt.x), min_split, std::max(min_split, limit));
            LayoutControls(rc.right, rc.bottom);
            ::InvalidateRect(hwnd_, nullptr, FALSE);
        } else if (menu_bar_) {
            if (menu_bar_->SetHot(menu_bar_->HitTest(pt))) {
                InvalidateMenuBar();
            }
        }
        return 0;
    }

    case WM_MOUSELEAVE:
        tracking_mouse_ = false;
        if (menu_bar_ && menu_bar_->SetHot(-1)) {
            InvalidateMenuBar();
        }
        return 0;

    case WM_LBUTTONUP:
        if (splitter_drag_) {
            splitter_drag_ = false;
            ::ReleaseCapture();
            SaveWindowState();
        }
        return 0;

    case WM_SETCURSOR: {
        if (reinterpret_cast<HWND>(wp) == hwnd_) {
            POINT pt{};
            ::GetCursorPos(&pt);
            ::ScreenToClient(hwnd_, &pt);
            const int split_w = fonts_.S(kSplitterDip);
            if (pt.x >= splitter_x_ && pt.x < splitter_x_ + split_w && pt.y >= fonts_.S(kMenuBarDip)) {
                ::SetCursor(::LoadCursorW(nullptr, IDC_SIZEWE));
                return TRUE;
            }
        }
        break;
    }

    case WM_SETTINGCHANGE:
        if (lp && _wcsicmp(reinterpret_cast<LPCWSTR>(lp), L"ImmersiveColorSet") == 0)
            UpdateTheme();
        return 0;

    case WM_APP + 1: {
        auto* result = reinterpret_cast<analysis::SafeAnalysisReport*>(lp);
        OnAnalysisDone(result);
        return 0;
    }

    case WM_DESTROY:
        if (analysis_thread_.joinable()) analysis_thread_.join();
        SaveWindowState();
        if (detail_) ::RemoveWindowSubclass(detail_, &KvcForensicWindow::DetailSubclassProc, 1);
        menu_bar_.reset();
        if (grid_pen_)   { ::DeleteObject(grid_pen_);  grid_pen_   = nullptr; }
        if (font_)       { ::DeleteObject(font_);      font_       = nullptr; }
        // accel_ loaded via LoadAcceleratorsW -- owned by the OS, not destroyed manually
        if (icon_big_)   { ::DestroyIcon(icon_big_);   icon_big_   = nullptr; }
        if (icon_small_) { ::DestroyIcon(icon_small_); icon_small_ = nullptr; }
        ::PostQuitMessage(0);
        return 0;

    default: break;
    }
    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------
void KvcForensicWindow::RecreateFonts(UINT dpi) {
    dpi_ = dpi ? dpi : 96;
    fonts_.Create(dpi_);

    if (font_) {
        ::DeleteObject(font_);
        font_ = nullptr;
    }
    LOGFONTW lf{};
    lf.lfHeight  = -fonts_.S(13);
    lf.lfWeight  = FW_NORMAL;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcscpy_s(lf.lfFaceName, fonts_.UiFamily());
    font_ = ::CreateFontIndirectW(&lf);

    if (tree_ && font_)   ::SendMessageW(tree_,   WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    if (detail_ && font_) ::SendMessageW(detail_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
}

void KvcForensicWindow::RestoreWindowState() {
    if (!hwnd_) return;

    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kSettingsKey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return;
    }

    DWORD splitter_dip = 0;
    DWORD splitter_size = sizeof(splitter_dip);
    if (::RegQueryValueExW(key, kSplitterDipValue, nullptr, nullptr,
                           reinterpret_cast<LPBYTE>(&splitter_dip), &splitter_size) == ERROR_SUCCESS &&
        splitter_size == sizeof(splitter_dip) && splitter_dip != 0) {
        splitter_x_ = fonts_.S(static_cast<int>(splitter_dip));
    }

    WINDOWPLACEMENT placement{};
    placement.length = sizeof(placement);
    DWORD placement_size = sizeof(placement);
    if (::RegQueryValueExW(key, kWindowPlacementValue, nullptr, nullptr,
                           reinterpret_cast<LPBYTE>(&placement), &placement_size) == ERROR_SUCCESS &&
        placement_size == sizeof(placement) && placement.length == sizeof(placement)) {
        const HMONITOR monitor = ::MonitorFromRect(
            &placement.rcNormalPosition, MONITOR_DEFAULTTONULL);
        const int width = placement.rcNormalPosition.right - placement.rcNormalPosition.left;
        const int height = placement.rcNormalPosition.bottom - placement.rcNormalPosition.top;
        if (monitor != nullptr && width >= fonts_.S(480) && height >= fonts_.S(320)) {
            placement.showCmd =
                (placement.showCmd == SW_SHOWMAXIMIZED) ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;
            if (::SetWindowPlacement(hwnd_, &placement)) {
                initial_show_cmd_ = placement.showCmd;
            }
        }
    }
    ::RegCloseKey(key);
}

void KvcForensicWindow::SaveWindowState() const {
    if (!hwnd_) return;

    HKEY key = nullptr;
    if (::RegCreateKeyExW(HKEY_CURRENT_USER, kSettingsKey, 0, nullptr, 0,
                          KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }

    WINDOWPLACEMENT placement{};
    placement.length = sizeof(placement);
    if (::GetWindowPlacement(hwnd_, &placement)) {
        ::RegSetValueExW(key, kWindowPlacementValue, 0, REG_BINARY,
                         reinterpret_cast<const BYTE*>(&placement), sizeof(placement));
    }

    const DWORD splitter_dip = static_cast<DWORD>(::MulDiv(
        splitter_x_, 96, static_cast<int>(dpi_ ? dpi_ : 96)));
    ::RegSetValueExW(key, kSplitterDipValue, 0, REG_DWORD,
                     reinterpret_cast<const BYTE*>(&splitter_dip), sizeof(splitter_dip));
    ::RegCloseKey(key);
}

void KvcForensicWindow::CreateControls(HWND hwnd) {
    const UINT init_dpi = ::GetDpiForWindow(hwnd);
    RecreateFonts(init_dpi);
    splitter_x_ = fonts_.S(280);

    // TreeView (left panel) — no legacy WS_EX_CLIENTEDGE; subtle D2D border painted around it
    tree_ = ::CreateWindowExW(
        0, WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS |
        TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT,
        0, 0, splitter_x_, 400,
        hwnd, nullptr, nullptr, nullptr);
    if (font_) ::SendMessageW(tree_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);

    // ListView detail panel (right) — custom-drawn subtle gridlines & dark/light header
    detail_ = ::CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
        splitter_x_ + fonts_.S(kSplitterDip), 0, 400, 400,
        hwnd, nullptr, nullptr, nullptr);
    ::SendMessageW(detail_, LVM_SETEXTENDEDLISTVIEWSTYLE,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    if (font_) ::SendMessageW(detail_, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    ::SetWindowSubclass(detail_, &KvcForensicWindow::DetailSubclassProc, 1, reinterpret_cast<DWORD_PTR>(this));

    // Detail columns: Property | Value
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    col.fmt  = LVCFMT_LEFT;
    col.cx   = fonts_.S(180);
    col.pszText = const_cast<wchar_t*>(L"Property");
    ListView_InsertColumn(detail_, 0, &col);
    col.cx      = fonts_.S(420);
    col.pszText = const_cast<wchar_t*>(L"Value");
    ListView_InsertColumn(detail_, 1, &col);

    // Initial status bar strings (rendered via Direct2D on Mica)
    status_text_[SB_FILE]  = L"No file loaded";
    status_text_[SB_BUILD] = L"";
    status_text_[SB_STATE] = L"Ready";

    // Direct2D MenuBar + owner-drawn popups + accelerators
    CreateAppMenu();

    // Layout
    RECT rc{};
    ::GetClientRect(hwnd, &rc);
    LayoutControls(rc.right, rc.bottom);
}

void KvcForensicWindow::CreateAppMenu() {
    menu_bar_ = std::make_unique<MenuBar>(fonts_);

    file_menu_ = menu_bar_->AddMenu(L"&File");
    menu_bar_->AddItem(file_menu_, IDM_FILE_OPEN, L"Open Dump...", L"Ctrl+O");
    menu_bar_->AddSeparator(file_menu_);
    menu_bar_->AddItem(file_menu_, IDM_FILE_EXIT, L"Exit", L"Alt+F4");

    view_menu_ = menu_bar_->AddMenu(L"&View");
    menu_bar_->AddItem(view_menu_, IDM_VIEW_ADVANCED, L"Advanced (show all accounts)");

    HMENU help_menu = menu_bar_->AddMenu(L"&Help");
    menu_bar_->AddItem(help_menu, IDM_HELP_ABOUT, L"About KvcForensic");

    context_menu_ = menu_bar_->CreatePopup();
    menu_bar_->AddItem(context_menu_, IDM_EDIT_COPY, L"Copy", L"Ctrl+C");

    accel_ = ::LoadAcceleratorsW(hInstance_, MAKEINTRESOURCEW(IDA_MAIN));
}

void KvcForensicWindow::LayoutControls(int w, int h) {
    const int pad      = fonts_.S(kOuterPadDip);
    const int menu_h   = fonts_.S(kMenuBarDip);
    const int status_h = fonts_.S(kStatusBarDip);
    const int split_w  = fonts_.S(kSplitterDip);

    if (menu_bar_) {
        menu_bar_->Layout(static_cast<float>(pad), fonts_.F(4.0f), static_cast<float>(menu_h - fonts_.S(8)));
    }

    const int top = menu_h + 1;
    const int content_h = std::max(0, h - top - status_h - 1);

    const int tree_x = pad + 1;
    const int tree_w = std::max(0, splitter_x_ - tree_x - 1);
    if (tree_) {
        ::MoveWindow(tree_, tree_x, top, tree_w, content_h, TRUE);
    }

    if (detail_) {
        const int dx = splitter_x_ + split_w + 1;
        const int dw = std::max(0, w - pad - dx - 1);
        ::MoveWindow(detail_, dx, top, dw, content_h, TRUE);

        const int prop_w = fonts_.S(180);
        const int val_w  = std::max(fonts_.S(80), dw - prop_w - fonts_.S(6));
        ListView_SetColumnWidth(detail_, 0, prop_w);
        ListView_SetColumnWidth(detail_, 1, val_w);
    }
}

void KvcForensicWindow::InvalidateMenuBar() {
    if (!hwnd_) return;
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    rc.bottom = fonts_.S(kMenuBarDip) + 2;
    ::InvalidateRect(hwnd_, &rc, FALSE);
}

void KvcForensicWindow::InvalidateStatusBar() {
    if (!hwnd_) return;
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    rc.top = std::max(0L, rc.bottom - fonts_.S(kStatusBarDip) - 2);
    ::InvalidateRect(hwnd_, &rc, FALSE);
}

void KvcForensicWindow::PaintWindow(HDC hdc) {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    if (rc.right <= rc.left || rc.bottom <= rc.top) return;

    const Palette& pal = Palette::For(is_dark_mode_);
    const int pad      = fonts_.S(kOuterPadDip);
    const int menu_h   = fonts_.S(kMenuBarDip);
    const int status_h = fonts_.S(kStatusBarDip);
    const int split_w  = fonts_.S(kSplitterDip);

    PaintD2D(hdc, rc, fonts_, [&](Canvas& c) {
        // Transparent on Mica (reveals DWM backdrop in extended top/bottom/side margins);
        // opaque base on Win10 / High Contrast.
        c.Clear(Graphics::Get().Base(is_dark_mode_));

        const float top_f = static_cast<float>(menu_h);
        const float bot_f = static_cast<float>(rc.bottom - status_h);

        // Interior band behind GDI child controls (outside extended Mica margins) is opaque
        // so TreeView/ListView scrollbars, headers, and gridlines keep full alpha.
        if (bot_f > top_f) {
            c.Fill({
                static_cast<float>(pad), top_f,
                static_cast<float>(rc.right - pad), bot_f
            }, pal.opaque_base);
        }

        // 1. Direct2D MenuBar + subtle bottom divider
        if (menu_bar_) menu_bar_->Paint(c);
        c.Line({0.0f, top_f - 0.5f}, {static_cast<float>(rc.right), top_f - 0.5f}, pal.divider);

        // 2. Hairline frames around TreeView & ListView + subtle splitter grip
        if (bot_f > top_f + 2.0f) {
            const D2D1_RECT_F tree_frame{
                static_cast<float>(pad), top_f,
                static_cast<float>(splitter_x_), bot_f
            };
            const D2D1_RECT_F detail_frame{
                static_cast<float>(splitter_x_ + split_w), top_f,
                static_cast<float>(rc.right - pad), bot_f
            };
            c.Stroke(tree_frame,   pal.divider, 0.0f, 1.0f);
            c.Stroke(detail_frame, pal.divider, 0.0f, 1.0f);

            // Centered subtle splitter grip pill
            const float gx = static_cast<float>(splitter_x_) + static_cast<float>(split_w) * 0.5f;
            const float gy = (top_f + bot_f) * 0.5f;
            const float gh = fonts_.F(18.0f);
            c.Fill({gx - 1.0f, gy - gh, gx + 1.0f, gy + gh}, pal.splitter_grip, 1.0f);
        }

        // 3. Direct2D Status bar (3 segments on Mica, with crisp top divider & warning highlight)
        const float sb_top = static_cast<float>(rc.bottom - status_h);
        const float sb_bot = static_cast<float>(rc.bottom);
        c.Line({0.0f, sb_top + 0.5f}, {static_cast<float>(rc.right), sb_top + 0.5f}, pal.divider);
        const float sb_l   = static_cast<float>(pad);
        const float sb_r   = static_cast<float>(rc.right - pad);

        const float w_total = std::max(0.0f, sb_r - sb_l);
        const float w_file  = std::min(fonts_.F(360.0f), w_total * 0.42f);
        const float w_build = std::min(fonts_.F(180.0f), w_total * 0.22f);
        const float x_build = sb_l + w_file;
        const float x_state = x_build + w_build;

        c.Text(status_text_[SB_FILE],  {sb_l + fonts_.F(4.0f), sb_top, x_build - fonts_.F(8.0f), sb_bot},
               Font::Caption, pal.text_secondary, Align::Left);
        if (!status_text_[SB_BUILD].empty()) {
            c.Line({x_build, sb_top + fonts_.F(7.0f)}, {x_build, sb_bot - fonts_.F(7.0f)}, pal.divider);
            c.Text(status_text_[SB_BUILD], {x_build + fonts_.F(10.0f), sb_top, x_state - fonts_.F(8.0f), sb_bot},
                   Font::Caption, pal.text_secondary, Align::Left);
        }

        const D2D1_RECT_F state_rc{x_state + fonts_.F(8.0f), sb_top + fonts_.F(4.0f), sb_r, sb_bot - fonts_.F(4.0f)};
        if (status_warning_) {
            c.Fill(state_rc, pal.warning_bg, fonts_.F(4.0f));
            c.Text(status_text_[SB_STATE], Inset(state_rc, fonts_.F(8.0f), 0.0f),
                   Font::Caption, pal.warning_text, Align::Left);
        } else {
            c.Line({x_state, sb_top + fonts_.F(7.0f)}, {x_state, sb_bot - fonts_.F(7.0f)}, pal.divider);
            c.Text(status_text_[SB_STATE], {x_state + fonts_.F(10.0f), sb_top, sb_r - fonts_.F(4.0f), sb_bot},
                   Font::Caption, pal.text_muted, Align::Left);
        }
    });
}

// ---------------------------------------------------------------------------
// Custom draw for ListView & Header (subtle theme-aware gridlines + dark header)
// ---------------------------------------------------------------------------
LRESULT CALLBACK KvcForensicWindow::DetailSubclassProc(
    HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    auto* self = reinterpret_cast<KvcForensicWindow*>(dwRefData);
    if (msg == WM_NOTIFY && self) {
        auto* nm = reinterpret_cast<NMHDR*>(lp);
        if (nm && nm->code == NM_CUSTOMDRAW && nm->hwndFrom == ListView_GetHeader(hwnd)) {
            return self->HandleHeaderCustomDraw(reinterpret_cast<NMCUSTOMDRAW*>(lp));
        }
    }
    if (msg == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, &KvcForensicWindow::DetailSubclassProc, uIdSubclass);
    }
    return ::DefSubclassProc(hwnd, msg, wp, lp);
}

LRESULT KvcForensicWindow::HandleHeaderCustomDraw(NMCUSTOMDRAW* cd) {
    if (!cd) return CDRF_DODEFAULT;
    const COLORREF bg   = is_dark_mode_ ? RGB(40, 40, 40)   : RGB(246, 246, 246);
    const COLORREF text = is_dark_mode_ ? RGB(228, 228, 228) : RGB(36, 36, 36);
    const COLORREF line = is_dark_mode_ ? RGB(60, 60, 60)   : RGB(222, 222, 222);

    if (cd->dwDrawStage == CDDS_PREPAINT) {
        RECT hdr_rc{};
        ::GetClientRect(cd->hdr.hwndFrom, &hdr_rc);
        HBRUSH br = ::CreateSolidBrush(bg);
        ::FillRect(cd->hdc, &hdr_rc, br);
        ::DeleteObject(br);

        HPEN pen = ::CreatePen(PS_SOLID, 1, line);
        HGDIOBJ old_pen = ::SelectObject(cd->hdc, pen);
        ::MoveToEx(cd->hdc, hdr_rc.left, hdr_rc.bottom - 1, nullptr);
        ::LineTo(cd->hdc, hdr_rc.right, hdr_rc.bottom - 1);
        ::SelectObject(cd->hdc, old_pen);
        ::DeleteObject(pen);
        return CDRF_NOTIFYITEMDRAW;
    }

    if (cd->dwDrawStage == CDDS_ITEMPREPAINT) {
        HBRUSH br = ::CreateSolidBrush(bg);
        ::FillRect(cd->hdc, &cd->rc, br);
        ::DeleteObject(br);

        HPEN pen = ::CreatePen(PS_SOLID, 1, line);
        HGDIOBJ old_pen = ::SelectObject(cd->hdc, pen);
        // Bottom border
        ::MoveToEx(cd->hdc, cd->rc.left, cd->rc.bottom - 1, nullptr);
        ::LineTo(cd->hdc, cd->rc.right, cd->rc.bottom - 1);
        // Right column separator
        ::MoveToEx(cd->hdc, cd->rc.right - 1, cd->rc.top + fonts_.S(4), nullptr);
        ::LineTo(cd->hdc, cd->rc.right - 1, cd->rc.bottom - fonts_.S(5));
        ::SelectObject(cd->hdc, old_pen);
        ::DeleteObject(pen);

        wchar_t label[128] = {};
        HDITEMW hdi{};
        hdi.mask = HDI_TEXT;
        hdi.pszText = label;
        hdi.cchTextMax = static_cast<int>(std::size(label));
        Header_GetItem(cd->hdr.hwndFrom, static_cast<int>(cd->dwItemSpec), &hdi);

        RECT text_rc = cd->rc;
        text_rc.left  += fonts_.S(8);
        text_rc.right -= fonts_.S(6);
        HGDIOBJ old_font = font_ ? ::SelectObject(cd->hdc, font_) : nullptr;
        ::SetBkMode(cd->hdc, TRANSPARENT);
        ::SetTextColor(cd->hdc, text);
        ::DrawTextW(cd->hdc, label, -1, &text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        if (old_font) ::SelectObject(cd->hdc, old_font);
        return CDRF_SKIPDEFAULT;
    }
    return CDRF_DODEFAULT;
}

LRESULT KvcForensicWindow::HandleListCustomDraw(NMLVCUSTOMDRAW* cd) {
    if (!cd) return CDRF_DODEFAULT;
    switch (cd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;

    case CDDS_ITEMPREPAINT: {
        const bool odd = (cd->nmcd.dwItemSpec & 1u) != 0;
        if (is_dark_mode_) {
            cd->clrTextBk = odd ? RGB(37, 37, 37) : RGB(32, 32, 32);
            cd->clrText   = RGB(240, 240, 240);
        } else {
            cd->clrTextBk = odd ? RGB(248, 249, 250) : RGB(255, 255, 255);
            cd->clrText   = RGB(24, 24, 24);
        }
        return CDRF_NEWFONT | CDRF_NOTIFYPOSTPAINT;
    }

    case CDDS_ITEMPOSTPAINT: {
        if (grid_pen_) {
            RECT rc{};
            ListView_GetItemRect(detail_, static_cast<int>(cd->nmcd.dwItemSpec), &rc, LVIR_BOUNDS);
            const int col0_w = ListView_GetColumnWidth(detail_, 0);
            HGDIOBJ old_pen = ::SelectObject(cd->nmcd.hdc, grid_pen_);
            // Subtle bottom horizontal rule
            ::MoveToEx(cd->nmcd.hdc, rc.left, rc.bottom - 1, nullptr);
            ::LineTo(cd->nmcd.hdc, rc.right, rc.bottom - 1);
            // Subtle vertical column divider
            if (col0_w > 0) {
                ::MoveToEx(cd->nmcd.hdc, rc.left + col0_w - 1, rc.top, nullptr);
                ::LineTo(cd->nmcd.hdc, rc.left + col0_w - 1, rc.bottom);
            }
            ::SelectObject(cd->nmcd.hdc, old_pen);
        }
        return CDRF_DODEFAULT;
    }

    default:
        return CDRF_DODEFAULT;
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
void KvcForensicWindow::UpdateTheme() {
    is_dark_mode_ = AppUseDarkMode();
    ApplyTheme();
}

void KvcForensicWindow::ApplyTheme() {
    SetUxThemePreferredAppMode(is_dark_mode_);

    if (grid_pen_) {
        ::DeleteObject(grid_pen_);
        grid_pen_ = nullptr;
    }
    grid_pen_ = ::CreatePen(PS_SOLID, 1, is_dark_mode_ ? RGB(52, 52, 52) : RGB(224, 224, 224));

    const MARGINS m{ fonts_.S(kOuterPadDip), fonts_.S(kOuterPadDip),
                     fonts_.S(kMenuBarDip),  fonts_.S(kStatusBarDip) };
    ApplyBackdrop(hwnd_, is_dark_mode_, m);
    if (menu_bar_) menu_bar_->SetDarkMode(is_dark_mode_);

    const Palette& pal = Palette::For(is_dark_mode_);

    if (is_dark_mode_) {
        if (tree_) {
            ::SetWindowTheme(tree_, L"DarkMode_Explorer", nullptr);
            TreeView_SetBkColor(tree_, pal.surface_bg);
            TreeView_SetTextColor(tree_, pal.surface_text);
        }
        if (detail_) {
            ::SetWindowTheme(detail_, L"DarkMode_Explorer", nullptr);
            ListView_SetBkColor(detail_, pal.surface_bg);
            ListView_SetTextBkColor(detail_, pal.surface_bg);
            ListView_SetTextColor(detail_, pal.surface_text);
            HWND hdr = ListView_GetHeader(detail_);
            if (hdr) ::SetWindowTheme(hdr, L"DarkMode_Header", nullptr);
        }
    } else {
        if (tree_) {
            ::SetWindowTheme(tree_, L"Explorer", nullptr);
            TreeView_SetBkColor(tree_, pal.surface_bg);
            TreeView_SetTextColor(tree_, pal.surface_text);
        }
        if (detail_) {
            ::SetWindowTheme(detail_, L"Explorer", nullptr);
            ListView_SetBkColor(detail_, pal.surface_bg);
            ListView_SetTextBkColor(detail_, pal.surface_bg);
            ListView_SetTextColor(detail_, pal.surface_text);
            HWND hdr = ListView_GetHeader(detail_);
            if (hdr) ::SetWindowTheme(hdr, L"Header", nullptr);
        }
    }

    ::RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

// ---------------------------------------------------------------------------
// File open
// ---------------------------------------------------------------------------
void KvcForensicWindow::OpenDumpDialog() {
    wchar_t buf[MAX_PATH] = L"lsass.dmp";
    OPENFILENAMEW ofn{};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hwnd_;
    ofn.lpstrFilter  = L"Dump files (*.dmp)\0*.dmp\0All files (*.*)\0*.*\0";
    ofn.lpstrFile    = buf;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrTitle   = L"Open LSASS Dump File";
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (::GetOpenFileNameW(&ofn))
        LoadDump(buf);
}

void KvcForensicWindow::LoadDump(const std::wstring& path) {
    if (analyzing_.load()) return;   // ignore while previous analysis is running

    if (analysis_thread_.joinable()) analysis_thread_.join();

    loaded_path_ = path;
    analyzing_.store(true);

    SetStatus(SB_FILE,  FileName(path).c_str());
    SetStatus(SB_BUILD, L"");
    SetStatus(SB_STATE, L"Analyzing...");
    SetStatusWarningMode(false);

    // Disable File > Open while busy
    if (file_menu_) ::EnableMenuItem(file_menu_, IDM_FILE_OPEN, MF_BYCOMMAND | MF_GRAYED);

    ::UpdateWindow(hwnd_);

    HWND hwnd = hwnd_;
    analysis_thread_ = std::thread([hwnd, path]() {
        analysis::SafeAnalysisEngine engine;
        auto* result = new analysis::SafeAnalysisReport(engine.AnalyzeFile(path));
        ::PostMessageW(hwnd, WM_APP + 1, 0, reinterpret_cast<LPARAM>(result));
    });
}

void KvcForensicWindow::SetStatusWarningMode(const bool warning) {
    if (status_warning_ == warning) return;
    status_warning_ = warning;
    InvalidateStatusBar();
}

void KvcForensicWindow::OnAnalysisDone(analysis::SafeAnalysisReport* result) {
    std::unique_ptr<analysis::SafeAnalysisReport> owned(result);

    if (analysis_thread_.joinable()) analysis_thread_.join();

    report_     = std::move(*owned);
    has_report_ = true;
    analyzing_.store(false);

    // Re-enable File > Open
    if (file_menu_) ::EnableMenuItem(file_menu_, IDM_FILE_OPEN, MF_BYCOMMAND | MF_ENABLED);

    if (report_.dump.system_info && report_.dump.system_info->valid) {
        const auto& si = *report_.dump.system_info;
        wchar_t build[64];
        swprintf_s(build, L"Build %u.%u.%u", si.major, si.minor, si.build);
        SetStatus(SB_BUILD, build);
    } else {
        SetStatus(SB_BUILD, L"Build unknown");
    }

    wchar_t state[64];
    if (report_.selected_template.used_runtime_fallback) {
        SetStatusWarningMode(true);
        SetStatus(SB_STATE, L"[!] Heuristic fallback used");
    } else if (report_.selected_template.used_heuristic_layout) {
        SetStatusWarningMode(true);
        SetStatus(SB_STATE, L"[!] Heuristic mode (template mismatch)");
    } else {
        SetStatusWarningMode(false);
        swprintf_s(state, L"%u session(s) found",
            static_cast<unsigned>(report_.sessions.size()));
        SetStatus(SB_STATE, state);
    }
    SetStatus(SB_FILE,  FileName(loaded_path_).c_str());

    PopulateTree();
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------
void KvcForensicWindow::PopulateTree() {
    ::SendMessageW(tree_, TVM_DELETEITEM, 0, reinterpret_cast<LPARAM>(TVI_ROOT));
    if (!has_report_) return;

    const auto& dump     = report_.dump;
    const auto& sessions = report_.sessions;

    // Helper: insert one tree item
    auto Insert = [&](HTREEITEM parent, const wchar_t* text, LPARAM param) -> HTREEITEM {
        TVINSERTSTRUCTW tvis{};
        tvis.hParent      = parent;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask    = TVIF_TEXT | TVIF_PARAM;
        tvis.item.pszText = const_cast<wchar_t*>(text);
        tvis.item.lParam  = param;
        return reinterpret_cast<HTREEITEM>(
            ::SendMessageW(tree_, TVM_INSERTITEM, 0, reinterpret_cast<LPARAM>(&tvis)));
    };

    // Root
    std::wstring root_label = L"Dump: " + FileName(dump.path);
    HTREEITEM root = Insert(TVI_ROOT, root_label.c_str(), EncodeNode(NodeType::Root));

    // Info
    Insert(root, L"Info", EncodeNode(NodeType::Info));

    // Modules
    wchar_t tmp[128];
    swprintf_s(tmp, L"Modules (%u)", (unsigned)dump.modules.size());
    HTREEITEM mods = Insert(root, tmp, EncodeNode(NodeType::Modules));
    const std::size_t mod_limit = std::min(dump.modules.size(), std::size_t(40));
    for (std::size_t i = 0; i < mod_limit; ++i) {
        std::wstring name = FileName(dump.modules[i].name);
        if (name.empty()) name = dump.modules[i].name;
        Insert(mods, name.c_str(), EncodeNode(NodeType::Module, (int)i));
    }
    if (dump.modules.size() > mod_limit) {
        swprintf_s(tmp, L"... (%u more)", (unsigned)(dump.modules.size() - mod_limit));
        Insert(mods, tmp, EncodeNode(NodeType::Modules));
    }

    // Streams
    swprintf_s(tmp, L"Streams (%u)", (unsigned)dump.streams.size());
    HTREEITEM stms = Insert(root, tmp, EncodeNode(NodeType::Streams));
    for (std::size_t i = 0; i < dump.streams.size(); ++i) {
        const auto& s = dump.streams[i];
        const wchar_t* label = s.type_name.empty() ? L"Unknown" : s.type_name.c_str();
        Insert(stms, label, EncodeNode(NodeType::Stream, (int)i));
    }

    std::vector<std::size_t> user_idx;
    std::vector<std::size_t> virtual_idx;
    std::vector<std::size_t> machine_idx;
    std::vector<std::size_t> system_idx;

    for (std::size_t i = 0; i < sessions.size(); ++i) {
        const auto& s = sessions[i];
        if (!ShouldShowSession(s, show_all_accounts_)) continue;
        switch (ClassifySession(s)) {
        case SessionClass::User:    user_idx.push_back(i); break;
        case SessionClass::Virtual: virtual_idx.push_back(i); break;
        case SessionClass::Machine: machine_idx.push_back(i); break;
        case SessionClass::System:  system_idx.push_back(i); break;
        default: break;
        }
    }

    const unsigned shown_sessions = static_cast<unsigned>(
        user_idx.size() + virtual_idx.size() + machine_idx.size() + system_idx.size());
    if (show_all_accounts_) {
        swprintf_s(tmp, L"Credentials (%u sessions)", shown_sessions);
    } else {
        swprintf_s(tmp, L"Credentials (%u/%u shown)", shown_sessions, (unsigned)sessions.size());
    }
    HTREEITEM creds_root = Insert(root, tmp, EncodeNode(NodeType::Credentials));

    auto InsertSessionGroup = [&](const wchar_t* label, const std::vector<std::size_t>& indices, bool expand_group) {
        if (indices.empty()) return;
        swprintf_s(tmp, L"%s (%u)", label, (unsigned)indices.size());
        HTREEITEM group = Insert(creds_root, tmp, EncodeNode(NodeType::Credentials));
        for (std::size_t i : indices) {
            const auto& s = sessions[i];
            const SessionClass cls = ClassifySession(s);
            swprintf_s(tmp, L"[%s] [%llx] %s",
                SessionTag(cls),
                s.authentication_id,
                s.username.empty() ? L"(none)" : s.username.c_str());
            HTREEITEM sess = Insert(group, tmp, EncodeNode(NodeType::Session, (int)i));

            if (!s.msv_credentials.empty()) {
                const auto msv_unique = CountUniqueBy(s.msv_credentials, BuildMsvKey);
                swprintf_s(tmp, L"MSV (%u/%u)", (unsigned)msv_unique, (unsigned)s.msv_credentials.size());
                Insert(sess, tmp, EncodeNode(NodeType::Msv, (int)i));
            }
            if (!s.credman_credentials.empty()) {
                const auto cred_unique = CountUniqueBy(s.credman_credentials, BuildCredmanKey);
                swprintf_s(tmp, L"CREDMAN (%u/%u)", (unsigned)cred_unique, (unsigned)s.credman_credentials.size());
                Insert(sess, tmp, EncodeNode(NodeType::CredMan, (int)i));
            }
            if (!s.wdigest_credentials.empty()) {
                const auto wd_unique = CountUniqueBy(s.wdigest_credentials, BuildWdigestKey);
                swprintf_s(tmp, L"WDigest (%u/%u)", (unsigned)wd_unique, (unsigned)s.wdigest_credentials.size());
                Insert(sess, tmp, EncodeNode(NodeType::WDigest, (int)i));
            }
            if (!s.kerberos_credentials.empty()) {
                const auto krb_unique = CountUniqueBy(s.kerberos_credentials, BuildKerberosKey);
                swprintf_s(tmp, L"Kerberos (%u/%u)", (unsigned)krb_unique, (unsigned)s.kerberos_credentials.size());
                Insert(sess, tmp, EncodeNode(NodeType::Kerberos, (int)i));
            }
            if (!s.dpapi_credentials.empty()) {
                const auto dpapi_unique = CountUniqueBy(s.dpapi_credentials, BuildDpapiKey);
                swprintf_s(tmp, L"DPAPI (%u/%u)", (unsigned)dpapi_unique, (unsigned)s.dpapi_credentials.size());
                Insert(sess, tmp, EncodeNode(NodeType::Dpapi, (int)i));
            }
        }
        if (expand_group) TreeView_Expand(tree_, group, TVE_EXPAND);
    };

    InsertSessionGroup(L"Users", user_idx, true);
    InsertSessionGroup(L"Virtual Accounts", virtual_idx, true);
    InsertSessionGroup(L"Machine/Service", machine_idx, true);
    if (show_all_accounts_) InsertSessionGroup(L"System/Internal", system_idx, false);

    // Expand root and credentials nodes
    TreeView_Expand(tree_, root,       TVE_EXPAND);
    TreeView_Expand(tree_, creds_root, TVE_EXPAND);
}

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------
void KvcForensicWindow::ClearDetail() {
    ListView_DeleteAllItems(detail_);
}

void KvcForensicWindow::AddDetailRow(const wchar_t* prop, const wchar_t* value) {
    int row = ListView_GetItemCount(detail_);
    LVITEMW item{};
    item.mask    = LVIF_TEXT;
    item.iItem   = row;
    item.pszText = const_cast<wchar_t*>(prop);
    ListView_InsertItem(detail_, &item);
    ListView_SetItemText(detail_, row, 1, const_cast<wchar_t*>(value));
}

void KvcForensicWindow::AddDetailRow(const wchar_t* prop, const std::wstring& value) {
    AddDetailRow(prop, value.c_str());
}

void KvcForensicWindow::ShowNodeDetail(LPARAM p) {
    ClearDetail();
    if (!has_report_) return;

    const NodeType type = GetNodeType(p);
    const int      idx  = GetNodeIndex(p);
    const auto& dump     = report_.dump;
    const auto& sessions = report_.sessions;

    wchar_t buf[256];

    switch (type) {

    case NodeType::Root:
    case NodeType::Info: {
        AddDetailRow(L"File",    dump.path.empty() ? L"(unknown)" : dump.path);
        swprintf_s(buf, L"%llu bytes", dump.file_size);
        AddDetailRow(L"Size",    buf);
        AddDetailRow(L"Valid",   dump.valid ? L"Yes" : L"No");
        if (dump.system_info && dump.system_info->valid) {
            const auto& si = *dump.system_info;
            swprintf_s(buf, L"%u.%u.%u", si.major, si.minor, si.build);
            AddDetailRow(L"Build", buf);
            AddDetailRow(L"Architecture",
                si.processor_architecture == 9 ? L"AMD64 (x64)" : L"x86");
        }
        swprintf_s(buf, L"%u", (unsigned)dump.modules.size());
        AddDetailRow(L"Modules",  buf);
        swprintf_s(buf, L"%u", (unsigned)dump.streams.size());
        AddDetailRow(L"Streams",  buf);
        swprintf_s(buf, L"%u", (unsigned)sessions.size());
        AddDetailRow(L"Sessions", buf);
        break;
    }

    case NodeType::Modules:
        swprintf_s(buf, L"%u", (unsigned)dump.modules.size());
        AddDetailRow(L"Total modules", buf);
        break;

    case NodeType::Module:
        if (idx >= 0 && (std::size_t)idx < dump.modules.size()) {
            const auto& m = dump.modules[idx];
            AddDetailRow(L"Name", m.name);
            swprintf_s(buf, L"0x%016llX", m.base_address);
            AddDetailRow(L"Base address", buf);
            swprintf_s(buf, L"%llu bytes", (unsigned long long)m.size);
            AddDetailRow(L"Size", buf);
        }
        break;

    case NodeType::Streams:
        swprintf_s(buf, L"%u", (unsigned)dump.streams.size());
        AddDetailRow(L"Total streams", buf);
        break;

    case NodeType::Stream:
        if (idx >= 0 && (std::size_t)idx < dump.streams.size()) {
            const auto& s = dump.streams[idx];
            swprintf_s(buf, L"%u", s.type);
            AddDetailRow(L"Type", buf);
            AddDetailRow(L"Name", s.type_name.empty() ? L"(unknown)" : s.type_name);
            swprintf_s(buf, L"0x%08X", s.rva);
            AddDetailRow(L"RVA", buf);
            swprintf_s(buf, L"%u bytes", s.data_size);
            AddDetailRow(L"Size", buf);
        }
        break;

    case NodeType::Credentials:
        swprintf_s(buf, L"%u", (unsigned)sessions.size());
        AddDetailRow(L"Sessions", buf);
        break;

    case NodeType::Session:
        if (idx >= 0 && (std::size_t)idx < sessions.size()) {
            const auto& s = sessions[idx];
            AddDetailRow(L"Account class", SessionTag(ClassifySession(s)));
            swprintf_s(buf, L"%llu  (0x%llx)", s.authentication_id, s.authentication_id);
            AddDetailRow(L"LUID",     buf);
            AddDetailRow(L"Username", s.username.empty()   ? L"(none)" : s.username);
            AddDetailRow(L"Domain",   s.domainname.empty() ? L"(none)" : s.domainname);
            AddDetailRow(L"SID",      s.sid.empty()        ? L"(none)" : ToWide(s.sid));
            swprintf_s(buf, L"%u", (unsigned)s.msv_credentials.size());
            AddDetailRow(L"MSV credentials raw", buf);
            swprintf_s(buf, L"%u", (unsigned)CountUniqueBy(s.msv_credentials, BuildMsvKey));
            AddDetailRow(L"MSV credentials unique", buf);
            swprintf_s(buf, L"%u", (unsigned)s.credman_credentials.size());
            AddDetailRow(L"CREDMAN credentials raw", buf);
            swprintf_s(buf, L"%u", (unsigned)CountUniqueBy(s.credman_credentials, BuildCredmanKey));
            AddDetailRow(L"CREDMAN credentials unique", buf);
            swprintf_s(buf, L"%u", (unsigned)s.wdigest_credentials.size());
            AddDetailRow(L"WDigest credentials raw", buf);
            swprintf_s(buf, L"%u", (unsigned)CountUniqueBy(s.wdigest_credentials, BuildWdigestKey));
            AddDetailRow(L"WDigest credentials unique", buf);
            swprintf_s(buf, L"%u", (unsigned)s.kerberos_credentials.size());
            AddDetailRow(L"Kerberos credentials raw", buf);
            swprintf_s(buf, L"%u", (unsigned)CountUniqueBy(s.kerberos_credentials, BuildKerberosKey));
            AddDetailRow(L"Kerberos credentials unique", buf);
            swprintf_s(buf, L"%u", (unsigned)s.dpapi_credentials.size());
            AddDetailRow(L"DPAPI masterkeys raw", buf);
            swprintf_s(buf, L"%u", (unsigned)CountUniqueBy(s.dpapi_credentials, BuildDpapiKey));
            AddDetailRow(L"DPAPI masterkeys unique", buf);
        }
        break;

    case NodeType::Msv:
        if (idx >= 0 && (std::size_t)idx < sessions.size()) {
            const auto& s = sessions[idx];
            if (s.msv_credentials.empty()) {
                AddDetailRow(L"Status", L"No MSV credentials");
                break;
            }
            const auto unique_idx = BuildUniqueIndices(s.msv_credentials, BuildMsvKey);
            swprintf_s(buf, L"%u", (unsigned)(s.msv_credentials.size() - unique_idx.size()));
            AddDetailRow(L"Duplicate entries filtered", buf);
            for (std::size_t i = 0; i < unique_idx.size(); ++i) {
                const auto& c = s.msv_credentials[unique_idx[i]];
                if (unique_idx.size() > 1) {
                    swprintf_s(buf, L"--- Credential %u ---", (unsigned)i + 1);
                    AddDetailRow(buf, L"");
                }
                if (!c.username.empty())   AddDetailRow(L"Username", c.username);
                if (!c.domainname.empty()) AddDetailRow(L"Domain",   c.domainname);
    if (!c.nt_hash.empty())    AddDetailRow(L"NT hash",  core::BytesToHex(c.nt_hash));
    if (!c.sha1_hash.empty())  AddDetailRow(L"SHA1",     core::BytesToHex(c.sha1_hash));
    if (!c.lm_hash.empty())    AddDetailRow(L"LM hash",  core::BytesToHex(c.lm_hash));
    if (!c.dpapi.empty())      AddDetailRow(L"DPAPI",    core::BytesToHex(c.dpapi));
                if (c.is_iso_protected)    AddDetailRow(L"ISO Protected", L"Yes");
            }
        }
        break;

    case NodeType::CredMan:
        if (idx >= 0 && (std::size_t)idx < sessions.size()) {
            const auto& s = sessions[idx];
            if (s.credman_credentials.empty()) {
                AddDetailRow(L"Status", L"No CREDMAN credentials");
                break;
            }
            const auto unique_idx = BuildUniqueIndices(s.credman_credentials, BuildCredmanKey);
            swprintf_s(buf, L"%u", (unsigned)(s.credman_credentials.size() - unique_idx.size()));
            AddDetailRow(L"Duplicate entries filtered", buf);
            for (std::size_t i = 0; i < unique_idx.size(); ++i) {
                const auto& c = s.credman_credentials[unique_idx[i]];
                if (unique_idx.size() > 1) {
                    swprintf_s(buf, L"--- Entry %u ---", (unsigned)i + 1);
                    AddDetailRow(buf, L"");
                }
                if (!c.username.empty())   AddDetailRow(L"Username", c.username);
                if (!c.domainname.empty()) AddDetailRow(L"Domain",   c.domainname);
                AddDetailRow(L"Password", c.password.empty() ? L"(none)" : c.password);
                if (c.password.empty() && !c.password_hex.empty()) AddDetailRow(L"Password (hex)", c.password_hex);
            }
        }
        break;

    case NodeType::WDigest:
        if (idx >= 0 && (std::size_t)idx < sessions.size()) {
            const auto& s = sessions[idx];
            if (s.wdigest_credentials.empty()) {
                AddDetailRow(L"Status", L"No WDigest credentials");
                break;
            }
            const auto unique_idx = BuildUniqueIndices(s.wdigest_credentials, BuildWdigestKey);
            swprintf_s(buf, L"%u", (unsigned)(s.wdigest_credentials.size() - unique_idx.size()));
            AddDetailRow(L"Duplicate entries filtered", buf);
            for (std::size_t i = 0; i < unique_idx.size(); ++i) {
                const auto& c = s.wdigest_credentials[unique_idx[i]];
                if (unique_idx.size() > 1) {
                    swprintf_s(buf, L"--- Entry %u ---", (unsigned)i + 1);
                    AddDetailRow(buf, L"");
                }
                if (!c.username.empty())   AddDetailRow(L"Username", c.username);
                if (!c.domainname.empty()) AddDetailRow(L"Domain",   c.domainname);
                AddDetailRow(L"Password", c.password.empty() ? L"(none)" : c.password);
                if (c.password.empty() && !c.password_hex.empty()) AddDetailRow(L"Password (hex)", c.password_hex);
            }
        }
        break;

    case NodeType::Kerberos:
        if (idx >= 0 && (std::size_t)idx < sessions.size()) {
            const auto& s = sessions[idx];
            if (s.kerberos_credentials.empty()) {
                AddDetailRow(L"Status", L"No Kerberos credentials");
                break;
            }
            const auto unique_idx = BuildUniqueIndices(s.kerberos_credentials, BuildKerberosKey);
            swprintf_s(buf, L"%u", (unsigned)(s.kerberos_credentials.size() - unique_idx.size()));
            AddDetailRow(L"Duplicate entries filtered", buf);
            for (std::size_t i = 0; i < unique_idx.size(); ++i) {
                const auto& c = s.kerberos_credentials[unique_idx[i]];
                if (unique_idx.size() > 1) {
                    swprintf_s(buf, L"--- Entry %u ---", (unsigned)i + 1);
                    AddDetailRow(buf, L"");
                }
                if (!c.username.empty())   AddDetailRow(L"Username", c.username);
                if (!c.domainname.empty()) AddDetailRow(L"Domain",   c.domainname);
                AddDetailRow(L"Password", c.password.empty() ? L"(none)" : c.password);
                if (c.password.empty() && !c.password_hex.empty()) AddDetailRow(L"Password (hex)", c.password_hex);
                for (std::size_t ti = 0; ti < c.tickets.size(); ++ti) {
                    const auto& t = c.tickets[ti];
                    const bool is_tgt = (_wcsicmp(t.service_name.c_str(), L"krbtgt") == 0);
                    swprintf_s(buf, L"--- Ticket %u%s ---", (unsigned)ti + 1, is_tgt ? L" [TGT]" : L"");
                    AddDetailRow(buf, L"");
                    if (!t.service_name.empty()) AddDetailRow(L"ServiceName", t.service_name);
                    if (!t.target_name.empty())  AddDetailRow(L"TargetName",  t.target_name);
                    if (!t.client_name.empty())  AddDetailRow(L"ClientName",  t.client_name);
                    swprintf_s(buf, L"0x%08X", t.flags);
                    AddDetailRow(L"Flags", std::wstring(buf) + L"  [" + DecodeTicketFlags(t.flags) + L"]");
                    AddDetailRow(L"EncType", EncTypeToString(t.enc_type));
                    swprintf_s(buf, L"%u", t.kvno);
                    AddDetailRow(L"Kvno (key version)", buf);
                    swprintf_s(buf, L"%u bytes", (unsigned)t.data.size());
                    AddDetailRow(L"Ticket size", buf);
                }
            }
        }
        break;

    case NodeType::Dpapi:
        if (idx >= 0 && (std::size_t)idx < sessions.size()) {
            const auto& s = sessions[idx];
            if (s.dpapi_credentials.empty()) {
                AddDetailRow(L"Status", L"No DPAPI masterkeys");
                break;
            }
            const auto unique_idx = BuildUniqueIndices(s.dpapi_credentials, BuildDpapiKey);
            swprintf_s(buf, L"%u", (unsigned)(s.dpapi_credentials.size() - unique_idx.size()));
            AddDetailRow(L"Duplicate entries filtered", buf);
            for (std::size_t i = 0; i < unique_idx.size(); ++i) {
                const auto& c = s.dpapi_credentials[unique_idx[i]];
                if (unique_idx.size() > 1) {
                    swprintf_s(buf, L"--- MasterKey %u ---", (unsigned)i + 1);
                    AddDetailRow(buf, L"");
                }
                swprintf_s(buf, L"%llu", (unsigned long long)c.luid);
                AddDetailRow(L"LUID", buf);
                AddDetailRow(L"key_guid",       core::Utf8ToWide(c.key_guid));
                AddDetailRow(L"masterkey",      core::BytesToHex(c.masterkey));
                AddDetailRow(L"sha1_masterkey", core::Utf8ToWide(c.sha1_masterkey));
            }
        }
        break;

    default:
        break;
    }
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------
void KvcForensicWindow::SetStatus(int part, const wchar_t* text) {
    if (part >= 0 && part < static_cast<int>(status_text_.size())) {
        status_text_[static_cast<std::size_t>(part)] = text ? text : L"";
        InvalidateStatusBar();
    }
}


// ---------------------------------------------------------------------------
// Clipboard copy
// ---------------------------------------------------------------------------
void KvcForensicWindow::CopySelectedRows() {
    if (!detail_) return;

    std::wstring text;
    int count = ListView_GetItemCount(detail_);
    wchar_t buf[1024];

    for (int i = 0; i < count; ++i) {
        if (!(ListView_GetItemState(detail_, i, LVIS_SELECTED) & LVIS_SELECTED))
            continue;

        buf[0] = L'\0';
        ListView_GetItemText(detail_, i, 0, buf, 1024);
        text += buf;
        text += L'\t';

        buf[0] = L'\0';
        ListView_GetItemText(detail_, i, 1, buf, 1024);
        text += buf;
        text += L'\n';
    }

    if (text.empty()) return;

    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hMem) return;
    void* ptr = ::GlobalLock(hMem);
    if (!ptr) { ::GlobalFree(hMem); return; }
    memcpy(ptr, text.c_str(), bytes);
    ::GlobalUnlock(hMem);

    if (::OpenClipboard(hwnd_)) {
        ::EmptyClipboard();
        ::SetClipboardData(CF_UNICODETEXT, hMem);
        ::CloseClipboard();
    } else {
        ::GlobalFree(hMem);
    }
}

} // namespace KvcForensic::ui
