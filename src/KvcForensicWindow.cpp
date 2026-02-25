#include "KvcForensicWindow.h"

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
// Constants
// ---------------------------------------------------------------------------
constexpr wchar_t kWndClass[]    = L"KvcForensicMainWnd";
constexpr int     kSplitterW     = 5;
constexpr int     kSplitterMin   = 120;

// Menu command IDs
constexpr WORD IDM_FILE_OPEN  = 0x0101;
constexpr WORD IDM_FILE_EXIT  = 0x0103;
constexpr WORD IDM_HELP_ABOUT = 0x0201;
constexpr WORD IDM_VIEW_ADVANCED = 0x0301;
constexpr WORD IDM_EDIT_COPY     = 0x0401;

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

void LoadShell32IconsByIndex(int index, HICON& large_icon, HICON& small_icon) {
    wchar_t sysdir[MAX_PATH] = {};
    const UINT n = ::GetSystemDirectoryW(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;

    std::wstring shell32_path = std::wstring(sysdir) + L"\\shell32.dll";
    HICON large_icon_tmp = nullptr;
    HICON small_icon_tmp = nullptr;
    UINT extracted = ::ExtractIconExW(shell32_path.c_str(), index, &large_icon_tmp, &small_icon_tmp, 1);
    if (extracted > 0) {
        if (large_icon_tmp) large_icon = large_icon_tmp;
        if (small_icon_tmp) small_icon = small_icon_tmp;
    }
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

enum class SessionClass {
    User,
    Virtual,
    Machine,
    System
};

SessionClass ClassifySession(const lsa::LogonSession& s) {
    const bool sid_virtual = s.sid.rfind("S-1-5-83-", 0) == 0;
    const bool sid_dwm = s.sid.rfind("S-1-5-90-", 0) == 0;
    const bool sid_umfd = s.sid.rfind("S-1-5-96-", 0) == 0;

    if (sid_virtual || ContainsI(s.domainname, L"virtual machine")) {
        return SessionClass::Virtual;
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
        || !s.kerberos_credentials.empty() || !s.dpapi_credentials.empty();
}

bool ShouldShowSession(const lsa::LogonSession& s, bool show_all_accounts) {
    if (show_all_accounts) return true;

    const SessionClass cls = ClassifySession(s);
    if (cls == SessionClass::User || cls == SessionClass::Virtual) return true;
    if (cls == SessionClass::Machine) return HasInterestingSecrets(s);
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
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    ::InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &KvcForensicWindow::WndProc;
    wc.hInstance     = instance;
    wc.hCursor       = ::LoadCursorW(nullptr, IDC_ARROW);
    LoadShell32IconsByIndex(104, icon_big_, icon_small_);
    if (!icon_big_ || !icon_small_) {
        LoadShell32IconsByIndex(103, icon_big_, icon_small_);
    }
    wc.hIcon         = icon_big_ ? icon_big_ : ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm       = icon_small_ ? icon_small_ : ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kWndClass;
    if (!::RegisterClassExW(&wc)) return false;

    hwnd_ = ::CreateWindowExW(
        0, kWndClass, L"KvcForensic",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 680,
        nullptr, nullptr, instance, this);
    if (!hwnd_) return false;

    ::SendMessageW(hwnd_, WM_SETICON, ICON_BIG,   reinterpret_cast<LPARAM>(wc.hIcon));
    ::SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(wc.hIconSm));

    UpdateTheme();
    ::ShowWindow(hwnd_, nCmdShow);
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
        self->hwnd_ = hwnd;  // set early so CreateControls / SetMenu can use hwnd_
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

    case WM_SIZE: {
        int w = LOWORD(lp), h = HIWORD(lp);
        // Clamp splitter to new width
        splitter_x_ = std::clamp(splitter_x_, kSplitterMin, std::max(kSplitterMin, w - kSplitterMin));
        LayoutControls(w, h);
        return 0;
    }

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
                L"Wahtsapp: +48 607-440-283",
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
        if (nm->hwndFrom == detail_ && nm->code == NM_RCLICK) {
            POINT pt; ::GetCursorPos(&pt);
            HMENU hCtx = ::CreatePopupMenu();
            int sel = ListView_GetSelectedCount(detail_);
            ::AppendMenuW(hCtx, MF_STRING | (sel > 0 ? 0 : MF_GRAYED),
                IDM_EDIT_COPY, L"Copy\tCtrl+C");
            ::TrackPopupMenu(hCtx, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd_, nullptr);
            ::DestroyMenu(hCtx);
        }
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int x = (short)LOWORD(lp);
        if (x >= splitter_x_ && x < splitter_x_ + kSplitterW) {
            splitter_drag_ = true;
            ::SetCapture(hwnd_);
            ::SetCursor(::LoadCursorW(nullptr, IDC_SIZEWE));
        }
        return 0;
    }

    case WM_MOUSEMOVE: {
        if (splitter_drag_) {
            int x = (short)LOWORD(lp);
            RECT rc; ::GetClientRect(hwnd_, &rc);
            int limit = rc.right - kSplitterMin;
            splitter_x_ = std::clamp(x, kSplitterMin, std::max(kSplitterMin, limit));
            LayoutControls(rc.right, rc.bottom);
        }
        return 0;
    }

    case WM_LBUTTONUP:
        if (splitter_drag_) {
            splitter_drag_ = false;
            ::ReleaseCapture();
        }
        return 0;

    case WM_SETCURSOR: {
        if ((HWND)wp == hwnd_) {
            POINT pt; ::GetCursorPos(&pt); ::ScreenToClient(hwnd_, &pt);
            if (pt.x >= splitter_x_ && pt.x < splitter_x_ + kSplitterW) {
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

    case WM_ERASEBKGND: {
        // Paint the splitter band in a contrasting color
        HDC hdc = reinterpret_cast<HDC>(wp);
        RECT rc; ::GetClientRect(hwnd, &rc);
        ::FillRect(hdc, &rc, bg_brush_ ? bg_brush_
                                       : reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1));
        return 1;
    }

    case WM_APP + 1: {
        auto* result = reinterpret_cast<analysis::SafeAnalysisReport*>(lp);
        OnAnalysisDone(result);
        return 0;
    }

    case WM_DESTROY:
        if (analysis_thread_.joinable()) analysis_thread_.join();
        if (font_)   ::DeleteObject(font_);
        if (bg_brush_) ::DeleteObject(bg_brush_);
        if (accel_)  ::DestroyAcceleratorTable(accel_);
        if (icon_big_) ::DestroyIcon(icon_big_);
        if (icon_small_) ::DestroyIcon(icon_small_);
        ::PostQuitMessage(0);
        return 0;

    default: break;
    }
    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------
void KvcForensicWindow::CreateControls(HWND hwnd) {
    // Font
    LOGFONTW lf{};
    lf.lfHeight = -14;
    lf.lfWeight = FW_NORMAL;
    wcscpy_s(lf.lfFaceName, L"Segoe UI");
    font_ = ::CreateFontIndirectW(&lf);

    // TreeView (left panel)
    tree_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS |
        TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0, 0, splitter_x_, 400,
        hwnd, nullptr, nullptr, nullptr);
    if (font_) ::SendMessageW(tree_, WM_SETFONT, (WPARAM)font_, TRUE);

    // ListView detail panel (right)
    detail_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
        splitter_x_ + kSplitterW, 0, 400, 400,
        hwnd, nullptr, nullptr, nullptr);
    ::SendMessageW(detail_, LVM_SETEXTENDEDLISTVIEWSTYLE,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    if (font_) ::SendMessageW(detail_, WM_SETFONT, (WPARAM)font_, TRUE);

    // Detail columns: Property | Value
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    col.fmt  = LVCFMT_LEFT;
    col.cx   = 160;
    col.pszText = const_cast<wchar_t*>(L"Property");
    ListView_InsertColumn(detail_, 0, &col);
    col.cx      = 400;
    col.pszText = const_cast<wchar_t*>(L"Value");
    ListView_InsertColumn(detail_, 1, &col);

    // Status bar
    status_bar_ = ::CreateWindowExW(
        0, STATUSCLASSNAME, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwnd, nullptr, nullptr, nullptr);
    if (font_) ::SendMessageW(status_bar_, WM_SETFONT, (WPARAM)font_, TRUE);

    // Set status bar parts (right edges; -1 = fill rest)
    int parts[3] = { 420, 620, -1 };
    ::SendMessageW(status_bar_, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
    SetStatus(SB_FILE,  L"No file loaded");
    SetStatus(SB_BUILD, L"");
    SetStatus(SB_STATE, L"Ready");

    // Menu + accelerators
    CreateAppMenu();

    // Layout
    RECT rc{}; ::GetClientRect(hwnd, &rc);
    LayoutControls(rc.right, rc.bottom);
}

void KvcForensicWindow::CreateAppMenu() {
    HMENU hFile = ::CreatePopupMenu();
    ::AppendMenuW(hFile, MF_STRING, IDM_FILE_OPEN, L"Open Dump...\tCtrl+O");
    ::AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(hFile, MF_STRING, IDM_FILE_EXIT, L"Exit");

    HMENU hHelp = ::CreatePopupMenu();
    ::AppendMenuW(hHelp, MF_STRING, IDM_HELP_ABOUT, L"About");

    view_menu_ = ::CreatePopupMenu();
    ::AppendMenuW(view_menu_, MF_STRING, IDM_VIEW_ADVANCED,
        L"Advanced (show all accounts)");

    HMENU hBar = ::CreateMenu();
    ::AppendMenuW(hBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFile), L"&File");
    ::AppendMenuW(hBar, MF_POPUP, reinterpret_cast<UINT_PTR>(view_menu_), L"&View");
    ::AppendMenuW(hBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hHelp), L"&Help");
    ::SetMenu(hwnd_, hBar);

    // Accelerator table
    ACCEL acc[] = {
        { FVIRTKEY | FCONTROL, 'O', IDM_FILE_OPEN },
        { FVIRTKEY | FCONTROL, 'C', IDM_EDIT_COPY },
    };
    accel_ = ::CreateAcceleratorTableW(acc, 2);
}

void KvcForensicWindow::LayoutControls(int w, int h) {
    // Status bar height
    int sbh = 0;
    if (status_bar_) {
        ::SendMessageW(status_bar_, WM_SIZE, 0, MAKELPARAM(w, h));
        RECT sbrc{}; ::GetWindowRect(status_bar_, &sbrc);
        sbh = sbrc.bottom - sbrc.top;
    }

    int content_h = std::max(0, h - sbh);

    if (tree_)
        ::MoveWindow(tree_, 0, 0, splitter_x_, content_h, TRUE);

    if (detail_) {
        int dx = splitter_x_ + kSplitterW;
        int dw = std::max(0, w - dx);
        ::MoveWindow(detail_, dx, 0, dw, content_h, TRUE);

        // Auto-size value column to fill remaining width
        int prop_w = 160;
        int val_w  = std::max(80, dw - prop_w - 4);
        ListView_SetColumnWidth(detail_, 0, prop_w);
        ListView_SetColumnWidth(detail_, 1, val_w);
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
    if (bg_brush_) { ::DeleteObject(bg_brush_); bg_brush_ = nullptr; }

    BOOL dark = is_dark_mode_;
    ::DwmSetWindowAttribute(hwnd_, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

    const wchar_t* theme = is_dark_mode_ ? L"DarkMode_Explorer" : L"Explorer";
    if (tree_)   ::SetWindowTheme(tree_,   theme, nullptr);
    if (detail_) ::SetWindowTheme(detail_, theme, nullptr);

    if (is_dark_mode_)
        bg_brush_ = ::CreateSolidBrush(RGB(40, 40, 40));
    else
        bg_brush_ = ::CreateSolidBrush(RGB(220, 220, 220));

    ::InvalidateRect(hwnd_, nullptr, TRUE);
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

    // Disable File > Open while busy
    HMENU hBar = ::GetMenu(hwnd_);
    if (hBar) ::EnableMenuItem(hBar, IDM_FILE_OPEN, MF_BYCOMMAND | MF_GRAYED);

    ::UpdateWindow(hwnd_);

    HWND hwnd = hwnd_;
    analysis_thread_ = std::thread([hwnd, path]() {
        analysis::SafeAnalysisEngine engine;
        auto* result = new analysis::SafeAnalysisReport(engine.AnalyzeFile(path));
        ::PostMessageW(hwnd, WM_APP + 1, 0, reinterpret_cast<LPARAM>(result));
    });
}

void KvcForensicWindow::OnAnalysisDone(analysis::SafeAnalysisReport* result) {
    std::unique_ptr<analysis::SafeAnalysisReport> owned(result);

    if (analysis_thread_.joinable()) analysis_thread_.join();

    report_     = std::move(*owned);
    has_report_ = true;
    analyzing_.store(false);

    // Re-enable File > Open
    HMENU hBar = ::GetMenu(hwnd_);
    if (hBar) ::EnableMenuItem(hBar, IDM_FILE_OPEN, MF_BYCOMMAND | MF_ENABLED);

    if (report_.dump.system_info && report_.dump.system_info->valid) {
        const auto& si = *report_.dump.system_info;
        wchar_t build[64];
        swprintf_s(build, L"Build %u.%u.%u", si.major, si.minor, si.build);
        SetStatus(SB_BUILD, build);
    } else {
        SetStatus(SB_BUILD, L"Build unknown");
    }

    wchar_t state[64];
    swprintf_s(state, L"%u session(s) found",
        static_cast<unsigned>(report_.sessions.size()));
    SetStatus(SB_STATE, state);
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
    if (status_bar_)
        ::SendMessageW(status_bar_, SB_SETTEXTW, (WPARAM)part, reinterpret_cast<LPARAM>(text));
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
