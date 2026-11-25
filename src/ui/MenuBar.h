#pragma once

#include "ui/D2DTheme.h"

#include <Windows.h>

#include <memory>
#include <string>
#include <vector>

namespace KvcForensic::ui {

// Direct2D menu bar painted directly onto the Mica client area, paired with
// theme-aware (Light + Dark) owner-drawn popup menus.
class MenuBar {
public:
    explicit MenuBar(const Fonts& fonts);
    ~MenuBar();
    MenuBar(const MenuBar&) = delete;
    MenuBar& operator=(const MenuBar&) = delete;

    void SetDarkMode(bool dark);

    HMENU AddMenu(std::wstring label);
    HMENU CreatePopup();
    void AddItem(HMENU menu, UINT id, std::wstring text, std::wstring shortcut = {}, bool radio = false);
    void AddSeparator(HMENU menu);
    void Remeasure();

    void Layout(float left, float top, float height);
    void Paint(Canvas& c) const;
    [[nodiscard]] D2D1_RECT_F Bounds() const;
    [[nodiscard]] int HitTest(POINT client) const;
    bool SetHot(int index);

    void Open(HWND owner, int index, bool keyboard);
    bool OpenByMnemonic(HWND owner, wchar_t key);
    void TrackContext(HWND owner, HMENU menu, POINT screen);

    void Measure(MEASUREITEMSTRUCT& mis) const;
    void Draw(const DRAWITEMSTRUCT& dis) const;

private:
    struct Data {
        std::wstring text;
        std::wstring shortcut;
        bool separator = false;
        bool radio = false;
    };
    struct Top {
        std::wstring label;
        wchar_t mnemonic = 0;
        HMENU menu = nullptr;
        D2D1_RECT_F rect{};
    };

    static LRESULT CALLBACK Filter(int code, WPARAM wParam, LPARAM lParam);
    void Prepare(HMENU menu);
    void Invalidate() const;

    const Fonts& fonts_;
    bool dark_mode_ = false;
    HBRUSH background_ = nullptr;
    std::vector<Top> tops_;
    std::vector<HMENU> popups_;
    std::vector<std::unique_ptr<Data>> data_;
    int hot_ = -1;
    int open_ = -1;
    int switch_to_ = -1;
    bool switch_by_keyboard_ = false;
    HWND owner_ = nullptr;
};

} // namespace KvcForensic::ui
