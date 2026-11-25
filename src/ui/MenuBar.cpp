#include "ui/MenuBar.h"

#include <algorithm>
#include <cmath>
#include <cwctype>

namespace KvcForensic::ui {
namespace {
MenuBar* g_tracking = nullptr;
constexpr wchar_t kIconCheck = L'\uE73E'; // Segoe Fluent Icons / MDL2 checkmark
} // namespace

MenuBar::MenuBar(const Fonts& fonts) : fonts_(fonts) {
    background_ = ::CreateSolidBrush(ToColorRef(Palette::For(dark_mode_).flyout));
}

MenuBar::~MenuBar() {
    for (auto& t : tops_) {
        if (t.menu) ::DestroyMenu(t.menu);
    }
    for (HMENU p : popups_) {
        if (p) ::DestroyMenu(p);
    }
    if (background_) ::DeleteObject(background_);
}

void MenuBar::SetDarkMode(bool dark) {
    dark_mode_ = dark;
    if (background_) ::DeleteObject(background_);
    background_ = ::CreateSolidBrush(ToColorRef(Palette::For(dark_mode_).flyout));
    for (auto& t : tops_) Prepare(t.menu);
    for (HMENU p : popups_) Prepare(p);
}

void MenuBar::Prepare(HMENU menu) {
    if (!menu) return;
    MENUINFO info{sizeof(info)};
    info.fMask = MIM_BACKGROUND | MIM_STYLE;
    info.hbrBack = background_;
    info.dwStyle = MNS_CHECKORBMP;
    ::SetMenuInfo(menu, &info);
}

HMENU MenuBar::AddMenu(std::wstring label) {
    wchar_t mnemonic = 0;
    if (const std::size_t amp = label.find(L'&'); amp != std::wstring::npos && amp + 1 < label.size()) {
        mnemonic = static_cast<wchar_t>(std::towlower(label[amp + 1]));
        label.erase(amp, 1);
    }
    HMENU menu = ::CreatePopupMenu();
    Prepare(menu);
    tops_.push_back({std::move(label), mnemonic, menu, {}});
    return menu;
}

HMENU MenuBar::CreatePopup() {
    HMENU menu = ::CreatePopupMenu();
    Prepare(menu);
    popups_.push_back(menu);
    return menu;
}

void MenuBar::AddItem(HMENU menu, UINT id, std::wstring text, std::wstring shortcut, bool radio) {
    auto d = std::make_unique<Data>(Data{std::move(text), std::move(shortcut), false, radio});
    MENUITEMINFOW item{sizeof(item)};
    item.fMask = MIIM_FTYPE | MIIM_ID | MIIM_DATA | MIIM_STRING;
    item.fType = MFT_OWNERDRAW | (radio ? MFT_RADIOCHECK : 0);
    item.wID = id;
    item.dwItemData = reinterpret_cast<ULONG_PTR>(d.get());
    item.dwTypeData = d->text.data();
    ::InsertMenuItemW(menu, ::GetMenuItemCount(menu), TRUE, &item);
    data_.push_back(std::move(d));
}

void MenuBar::AddSeparator(HMENU menu) {
    auto d = std::make_unique<Data>(Data{{}, {}, true, false});
    MENUITEMINFOW item{sizeof(item)};
    item.fMask = MIIM_FTYPE | MIIM_DATA;
    item.fType = MFT_OWNERDRAW | MFT_SEPARATOR;
    item.dwItemData = reinterpret_cast<ULONG_PTR>(d.get());
    ::InsertMenuItemW(menu, ::GetMenuItemCount(menu), TRUE, &item);
    data_.push_back(std::move(d));
}

void MenuBar::Remeasure() {
    auto touch = [](HMENU menu) {
        if (!menu) return;
        const int count = ::GetMenuItemCount(menu);
        for (int i = 0; i < count; ++i) {
            MENUITEMINFOW item{sizeof(item)};
            item.fMask = MIIM_FTYPE;
            if (::GetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item))
                ::SetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item);
        }
    };
    for (auto& t : tops_) touch(t.menu);
    for (HMENU p : popups_) touch(p);
}

void MenuBar::Layout(float left, float top, float height) {
    float x = left;
    for (auto& t : tops_) {
        const float w = TextWidth(fonts_, Font::Body, t.label) + fonts_.F(20.0f);
        t.rect = {x, top, x + w, top + height};
        x += w + fonts_.F(2.0f);
    }
}

D2D1_RECT_F MenuBar::Bounds() const {
    if (tops_.empty()) return {};
    return {tops_.front().rect.left, tops_.front().rect.top, tops_.back().rect.right, tops_.back().rect.bottom};
}

void MenuBar::Paint(Canvas& c) const {
    const Palette& pal = Palette::For(dark_mode_);
    for (std::size_t i = 0; i < tops_.size(); ++i) {
        const auto& t = tops_[i];
        const int index = static_cast<int>(i);
        if (index == open_) c.Fill(t.rect, pal.selected, fonts_.F(4.0f));
        else if (index == hot_) c.Fill(t.rect, pal.hover, fonts_.F(4.0f));
        c.Text(t.label, t.rect, Font::Body,
               (index == open_ || index == hot_) ? pal.text : pal.text_secondary,
               Align::Center);
    }
}

int MenuBar::HitTest(POINT p) const {
    const float x = static_cast<float>(p.x);
    const float y = static_cast<float>(p.y);
    for (std::size_t i = 0; i < tops_.size(); ++i) {
        const auto& r = tops_[i].rect;
        if (x >= r.left && x < r.right && y >= r.top && y < r.bottom) return static_cast<int>(i);
    }
    return -1;
}

bool MenuBar::SetHot(int index) {
    if (index == hot_) return false;
    hot_ = index;
    return true;
}

void MenuBar::Invalidate() const {
    if (!owner_) return;
    const D2D1_RECT_F b = Bounds();
    RECT r{
        static_cast<LONG>(b.left) - 2,
        static_cast<LONG>(b.top) - 2,
        static_cast<LONG>(b.right) + 2,
        static_cast<LONG>(b.bottom) + 2
    };
    ::InvalidateRect(owner_, &r, FALSE);
    ::UpdateWindow(owner_);
}

LRESULT CALLBACK MenuBar::Filter(int code, WPARAM wParam, LPARAM lParam) {
    MenuBar* self = g_tracking;
    if (code == MSGF_MENU && self && self->open_ >= 0) {
        const MSG& msg = *reinterpret_cast<const MSG*>(lParam);
        const int count = static_cast<int>(self->tops_.size());
        if (msg.message == WM_KEYDOWN && (msg.wParam == VK_LEFT || msg.wParam == VK_RIGHT) && count > 1) {
            self->switch_to_ = (self->open_ + (msg.wParam == VK_RIGHT ? 1 : count - 1)) % count;
            self->switch_by_keyboard_ = true;
            ::EndMenu();
            return TRUE;
        }
        if (msg.message == WM_MOUSEMOVE || msg.message == WM_LBUTTONDOWN) {
            POINT p = msg.pt;
            ::ScreenToClient(self->owner_, &p);
            const int index = self->HitTest(p);
            if (msg.message == WM_MOUSEMOVE && index >= 0 && index != self->open_) {
                self->switch_to_ = index;
                self->switch_by_keyboard_ = false;
                ::EndMenu();
                return TRUE;
            }
            if (msg.message == WM_LBUTTONDOWN && index == self->open_) {
                self->switch_to_ = -1;
                ::EndMenu();
                return TRUE;
            }
        }
    }
    return ::CallNextHookEx(nullptr, code, wParam, lParam);
}

void MenuBar::Open(HWND owner, int index, bool keyboard) {
    if (index < 0 || index >= static_cast<int>(tops_.size()) || g_tracking) return;
    owner_ = owner;
    UINT command = 0;
    while (index >= 0) {
        open_ = index;
        switch_to_ = -1;
        Invalidate();

        const auto& t = tops_[static_cast<std::size_t>(index)];
        POINT top_left{static_cast<LONG>(t.rect.left), static_cast<LONG>(t.rect.top)};
        POINT bottom_right{static_cast<LONG>(t.rect.right), static_cast<LONG>(t.rect.bottom)};
        ::ClientToScreen(owner, &top_left);
        ::ClientToScreen(owner, &bottom_right);
        TPMPARAMS params{sizeof(params), {top_left.x, top_left.y, bottom_right.x, bottom_right.y}};
        if (keyboard) ::PostMessageW(owner, WM_KEYDOWN, VK_DOWN, 0);

        g_tracking = this;
        HHOOK hook = ::SetWindowsHookExW(WH_MSGFILTER, Filter, nullptr, ::GetCurrentThreadId());
        command = static_cast<UINT>(::TrackPopupMenuEx(
            t.menu,
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_VERTICAL | TPM_RETURNCMD,
            top_left.x, bottom_right.y, owner, &params));
        if (hook) ::UnhookWindowsHookEx(hook);
        g_tracking = nullptr;

        if (command) break;
        index = switch_to_;
        keyboard = switch_by_keyboard_;
    }

    open_ = -1;
    POINT cursor{};
    ::GetCursorPos(&cursor);
    ::ScreenToClient(owner, &cursor);
    hot_ = HitTest(cursor);
    Invalidate();
    if (command) ::PostMessageW(owner, WM_COMMAND, MAKEWPARAM(command, 0), 0);
}

bool MenuBar::OpenByMnemonic(HWND owner, wchar_t key) {
    key = static_cast<wchar_t>(std::towlower(key));
    for (std::size_t i = 0; i < tops_.size(); ++i) {
        if (tops_[i].mnemonic && tops_[i].mnemonic == key) {
            Open(owner, static_cast<int>(i), true);
            return true;
        }
    }
    return false;
}

void MenuBar::TrackContext(HWND owner, HMENU menu, POINT screen) {
    const UINT command = static_cast<UINT>(::TrackPopupMenuEx(
        menu,
        TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
        screen.x, screen.y, owner, nullptr));
    if (command) ::PostMessageW(owner, WM_COMMAND, MAKEWPARAM(command, 0), 0);
}

void MenuBar::Measure(MEASUREITEMSTRUCT& mis) const {
    const auto* d = reinterpret_cast<const Data*>(mis.itemData);
    if (!d) return;
    if (d->separator) {
        mis.itemWidth = static_cast<UINT>(fonts_.S(40));
        mis.itemHeight = static_cast<UINT>(fonts_.S(9));
        return;
    }
    const float text = TextWidth(fonts_, Font::Body, d->text);
    const float shortcut = d->shortcut.empty()
        ? 0.0f
        : TextWidth(fonts_, Font::Caption, d->shortcut) + fonts_.F(32.0f);
    mis.itemWidth = static_cast<UINT>(fonts_.F(36.0f) + text + shortcut + fonts_.F(16.0f));
    mis.itemHeight = static_cast<UINT>(fonts_.S(30));
}

void MenuBar::Draw(const DRAWITEMSTRUCT& dis) const {
    const auto* d = reinterpret_cast<const Data*>(dis.itemData);
    if (!d) return;
    const bool disabled = (dis.itemState & (ODS_DISABLED | ODS_GRAYED)) != 0;
    const bool selected = ((dis.itemState & ODS_SELECTED) != 0) && !disabled;
    const bool checked = (dis.itemState & ODS_CHECKED) != 0;
    const Palette& pal = Palette::For(dark_mode_);
    const auto& f = fonts_;

    PaintD2D(dis.hDC, dis.rcItem, f, [&](Canvas& c) {
        const D2D1_RECT_F r = ToF(dis.rcItem);
        c.Clear(pal.flyout);
        if (d->separator) {
            const float y = std::floor((r.top + r.bottom) * 0.5f) + 0.5f;
            c.Line({r.left + f.F(6.0f), y}, {r.right - f.F(6.0f), y}, pal.flyout_stroke);
            return;
        }
        if (selected) c.Fill(Inset(r, f.F(4.0f), f.F(2.0f)), pal.flyout_hot, f.F(4.0f));
        const D2D1_COLOR_F fg = disabled ? pal.text_disabled : pal.text;
        if (checked) {
            if (d->radio) {
                c.Circle({r.left + f.F(20.0f), (r.top + r.bottom) * 0.5f},
                         f.F(3.5f), disabled ? pal.text_disabled : pal.accent);
            } else {
                const wchar_t check_str[2] = {kIconCheck, L'\0'};
                c.Text(check_str, {r.left + f.F(10.0f), r.top, r.left + f.F(30.0f), r.bottom},
                       Font::IconSmall, fg, Align::Center);
            }
        }
        c.Text(d->text, {r.left + f.F(36.0f), r.top, r.right - f.F(12.0f), r.bottom}, Font::Body, fg);
        if (!d->shortcut.empty()) {
            c.Text(d->shortcut, {r.left, r.top, r.right - f.F(16.0f), r.bottom},
                   Font::Caption, disabled ? pal.text_disabled : pal.text_muted, Align::Right);
        }
    });
}

} // namespace KvcForensic::ui
