#pragma once

#include <Windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <uxtheme.h>
#include <wrl/client.h>

#include <array>
#include <functional>
#include <string_view>

namespace KvcForensic::ui {

using Microsoft::WRL::ComPtr;

constexpr D2D1_COLOR_F Rgb(unsigned hex, float alpha = 1.0f) {
    return {
        static_cast<float>((hex >> 16) & 0xFF) / 255.0f,
        static_cast<float>((hex >> 8) & 0xFF) / 255.0f,
        static_cast<float>(hex & 0xFF) / 255.0f,
        alpha
    };
}
constexpr D2D1_COLOR_F White(float alpha) { return {1.0f, 1.0f, 1.0f, alpha}; }
constexpr D2D1_COLOR_F Black(float alpha) { return {0.0f, 0.0f, 0.0f, alpha}; }

COLORREF ToColorRef(D2D1_COLOR_F c);

struct Palette {
    D2D1_COLOR_F text{};
    D2D1_COLOR_F text_secondary{};
    D2D1_COLOR_F text_muted{};
    D2D1_COLOR_F text_disabled{};

    D2D1_COLOR_F hover{};
    D2D1_COLOR_F selected{};
    D2D1_COLOR_F divider{};
    D2D1_COLOR_F splitter_grip{};
    D2D1_COLOR_F accent{};

    D2D1_COLOR_F flyout{};
    D2D1_COLOR_F flyout_hot{};
    D2D1_COLOR_F flyout_stroke{};

    D2D1_COLOR_F opaque_base{};
    D2D1_COLOR_F warning_bg{};
    D2D1_COLOR_F warning_text{};

    COLORREF surface_bg = RGB(32, 32, 32);
    COLORREF surface_text = RGB(255, 255, 255);

    static const Palette& Dark() noexcept;
    static const Palette& Light() noexcept;
    static const Palette& For(bool dark) noexcept { return dark ? Dark() : Light(); }
};

enum class Font : std::size_t { Body, Strong, Caption, IconSmall, Count };

// DPI-scaled DirectWrite text formats (physical pixels; render targets run at 96 DPI).
class Fonts {
public:
    void Create(UINT dpi);
    [[nodiscard]] IDWriteTextFormat* operator[](Font f) const { return formats_[static_cast<std::size_t>(f)].Get(); }
    [[nodiscard]] UINT dpi() const noexcept { return dpi_; }
    [[nodiscard]] int S(int v) const noexcept { return ::MulDiv(v, static_cast<int>(dpi_), 96); }
    [[nodiscard]] float F(float v) const noexcept { return v * static_cast<float>(dpi_) / 96.0f; }
    [[nodiscard]] const wchar_t* UiFamily() const noexcept { return ui_family_; }

private:
    UINT dpi_ = 96;
    const wchar_t* ui_family_ = L"Segoe UI";
    std::array<ComPtr<IDWriteTextFormat>, static_cast<std::size_t>(Font::Count)> formats_;
};

// Process-wide Direct2D / DirectWrite factories and reusable premultiplied 32-bit DIB buffer.
class Graphics {
public:
    static Graphics& Get();
    [[nodiscard]] bool Ready() const noexcept { return d2d_ && dwrite_; }
    [[nodiscard]] ID2D1Factory* D2D() const noexcept { return d2d_.Get(); }
    [[nodiscard]] IDWriteFactory* DWrite() const noexcept { return dwrite_.Get(); }
    ID2D1DCRenderTarget* Target();
    void ResetTarget() { target_.Reset(); }
    bool HasFamily(const wchar_t* family) const;

    bool mica = false;
    [[nodiscard]] D2D1_COLOR_F Base(bool dark) const noexcept {
        return mica ? Black(0.0f) : Palette::For(dark).opaque_base;
    }

    HDC Buffer(int width, int height);

private:
    Graphics();
    ~Graphics();

    ComPtr<ID2D1Factory> d2d_;
    ComPtr<IDWriteFactory> dwrite_;
    ComPtr<ID2D1DCRenderTarget> target_;
    HDC mem_dc_ = nullptr;
    HBITMAP dib_ = nullptr;
    HGDIOBJ old_bitmap_ = nullptr;
    int buffer_width_ = 0;
    int buffer_height_ = 0;
};

enum class Align { Left, Center, Right };

class Canvas {
public:
    Canvas(ID2D1RenderTarget& target, const Fonts& fonts);

    void Clear(D2D1_COLOR_F c);
    void Fill(const D2D1_RECT_F& r, D2D1_COLOR_F c, float radius = 0.0f);
    void Stroke(const D2D1_RECT_F& r, D2D1_COLOR_F c, float radius = 0.0f, float width = 1.0f);
    void Line(D2D1_POINT_2F a, D2D1_POINT_2F b, D2D1_COLOR_F c, float width = 1.0f);
    void Circle(D2D1_POINT_2F center, float radius, D2D1_COLOR_F c);
    void Text(std::wstring_view text, const D2D1_RECT_F& r, Font font, D2D1_COLOR_F c, Align align = Align::Left);

private:
    ID2D1SolidColorBrush* Brush(D2D1_COLOR_F c);
    ID2D1RenderTarget& rt_;
    const Fonts& fonts_;
    ComPtr<ID2D1SolidColorBrush> brush_;
};

float TextWidth(const Fonts& fonts, Font font, std::wstring_view text);

// Paints `rect` (client coordinates of `dc`) through the shared premultiplied 32-bit DIB.
void PaintD2D(HDC dc, const RECT& rect, const Fonts& fonts, const std::function<void(Canvas&)>& draw);

constexpr D2D1_RECT_F ToF(const RECT& r) {
    return {
        static_cast<float>(r.left),
        static_cast<float>(r.top),
        static_cast<float>(r.right),
        static_cast<float>(r.bottom)
    };
}
constexpr D2D1_RECT_F Inset(const D2D1_RECT_F& r, float dx, float dy) {
    return {r.left + dx, r.top + dy, r.right - dx, r.bottom - dy};
}

// Applies immersive dark/light title bar + Mica backdrop (or opaque fallback on Win10 / High Contrast).
// Pass explicit `margins` so Mica covers the menu/status chrome without corrupting GDI child controls.
void ApplyBackdrop(HWND window, bool dark_mode, MARGINS margins);

} // namespace KvcForensic::ui
