#include "ui/D2DTheme.h"

#include <dwmapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <cmath>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "gdi32.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_SYSTEMBACKDROP_TYPE
#define DWMWA_SYSTEMBACKDROP_TYPE 38
#endif

namespace KvcForensic::ui {

COLORREF ToColorRef(D2D1_COLOR_F c) {
    auto byte = [](float v) { return static_cast<BYTE>(std::lround(std::clamp(v, 0.0f, 1.0f) * 255.0f)); };
    return RGB(byte(c.r), byte(c.g), byte(c.b));
}

const Palette& Palette::Dark() noexcept {
    static const Palette p{
        /* text           */ White(1.000f),
        /* text_secondary */ White(0.786f),
        /* text_muted     */ White(0.545f),
        /* text_disabled  */ White(0.363f),
        /* hover          */ White(0.060f),
        /* selected       */ White(0.100f),
        /* divider        */ White(0.085f),
        /* splitter_grip  */ White(0.240f),
        /* accent         */ Rgb(0x60CDFF),
        /* flyout         */ Rgb(0x2C2C2C),
        /* flyout_hot     */ Rgb(0x3A3A3A),
        /* flyout_stroke  */ Rgb(0x454545),
        /* opaque_base    */ Rgb(0x202020),
        /* warning_bg     */ Rgb(0x9E2A2B, 0.92f),
        /* warning_text   */ White(1.000f),
        /* surface_bg     */ RGB(32, 32, 32),
        /* surface_text   */ RGB(245, 245, 245),
    };
    return p;
}

const Palette& Palette::Light() noexcept {
    static const Palette p{
        /* text           */ Black(0.900f),
        /* text_secondary */ Black(0.650f),
        /* text_muted     */ Black(0.450f),
        /* text_disabled  */ Black(0.360f),
        /* hover          */ Black(0.045f),
        /* selected       */ Black(0.080f),
        /* divider        */ Black(0.090f),
        /* splitter_grip  */ Black(0.220f),
        /* accent         */ Rgb(0x005FB8),
        /* flyout         */ Rgb(0xF9F9F9),
        /* flyout_hot     */ Rgb(0xEBEBEB),
        /* flyout_stroke  */ Rgb(0xDFDFDF),
        /* opaque_base    */ Rgb(0xF3F3F3),
        /* warning_bg     */ Rgb(0xC42B1C, 0.92f),
        /* warning_text   */ White(1.000f),
        /* surface_bg     */ RGB(255, 255, 255),
        /* surface_text   */ RGB(24, 24, 24),
    };
    return p;
}

// ---------------------------------------------------------------------------
// Graphics
// ---------------------------------------------------------------------------
Graphics& Graphics::Get() {
    static Graphics instance;
    return instance;
}

Graphics::Graphics() {
    D2D1_FACTORY_OPTIONS options{};
    ::D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, __uuidof(ID2D1Factory), &options,
                        reinterpret_cast<void**>(d2d_.GetAddressOf()));
    ::DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                          reinterpret_cast<IUnknown**>(dwrite_.GetAddressOf()));
}

Graphics::~Graphics() {
    if (mem_dc_ && old_bitmap_) ::SelectObject(mem_dc_, old_bitmap_);
    if (dib_) ::DeleteObject(dib_);
    if (mem_dc_) ::DeleteDC(mem_dc_);
}

ID2D1DCRenderTarget* Graphics::Target() {
    if (!target_ && d2d_) {
        const auto props = D2D1::RenderTargetProperties(
            D2D1_RENDER_TARGET_TYPE_SOFTWARE,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED),
            96.0f, 96.0f);
        d2d_->CreateDCRenderTarget(&props, target_.GetAddressOf());
    }
    return target_.Get();
}

bool Graphics::HasFamily(const wchar_t* family) const {
    if (!dwrite_) return false;
    ComPtr<IDWriteFontCollection> fonts;
    if (FAILED(dwrite_->GetSystemFontCollection(fonts.GetAddressOf(), FALSE))) return false;
    UINT32 index = 0;
    BOOL exists = FALSE;
    return SUCCEEDED(fonts->FindFamilyName(family, &index, &exists)) && exists;
}

HDC Graphics::Buffer(int width, int height) {
    width = std::max(width, 1);
    height = std::max(height, 1);
    if (mem_dc_ && width <= buffer_width_ && height <= buffer_height_) return mem_dc_;
    if (!mem_dc_) mem_dc_ = ::CreateCompatibleDC(nullptr);
    if (!mem_dc_) return nullptr;
    if (old_bitmap_) {
        ::SelectObject(mem_dc_, old_bitmap_);
        old_bitmap_ = nullptr;
    }
    if (dib_) {
        ::DeleteObject(dib_);
        dib_ = nullptr;
    }
    const int bw = std::max(buffer_width_, (width + 255) & ~255);
    const int bh = std::max(buffer_height_, (height + 255) & ~255);
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = bw;
    info.bmiHeader.biHeight = -bh; // top-down
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    dib_ = ::CreateDIBSection(mem_dc_, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!dib_) {
        buffer_width_ = buffer_height_ = 0;
        return nullptr;
    }
    buffer_width_ = bw;
    buffer_height_ = bh;
    old_bitmap_ = ::SelectObject(mem_dc_, dib_);
    return mem_dc_;
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------
void Fonts::Create(UINT dpi) {
    dpi_ = dpi ? dpi : 96;
    auto& g = Graphics::Get();
    if (!g.DWrite()) return;

    ui_family_ = g.HasFamily(L"Segoe UI Variable Text") ? L"Segoe UI Variable Text" : L"Segoe UI";
    const wchar_t* icons = g.HasFamily(L"Segoe Fluent Icons") ? L"Segoe Fluent Icons" : L"Segoe MDL2 Assets";

    struct Spec {
        Font font;
        const wchar_t* family;
        float size;
        DWRITE_FONT_WEIGHT weight;
    };
    const Spec specs[] = {
        {Font::Body,      ui_family_, 13.0f, DWRITE_FONT_WEIGHT_NORMAL},
        {Font::Strong,    ui_family_, 13.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD},
        {Font::Caption,   ui_family_, 11.5f, DWRITE_FONT_WEIGHT_NORMAL},
        {Font::IconSmall, icons,      10.5f, DWRITE_FONT_WEIGHT_NORMAL},
    };

    ComPtr<IDWriteInlineObject> ellipsis;
    for (const Spec& s : specs) {
        auto& slot = formats_[static_cast<std::size_t>(s.font)];
        slot.Reset();
        const float size = F(s.size);
        if (FAILED(g.DWrite()->CreateTextFormat(s.family, nullptr, s.weight, DWRITE_FONT_STYLE_NORMAL,
                                                DWRITE_FONT_STRETCH_NORMAL, size, L"en-us", slot.GetAddressOf())))
            continue;
        slot->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
        slot->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        if (g.DWrite()->CreateEllipsisTrimmingSign(slot.Get(), ellipsis.ReleaseAndGetAddressOf()) == S_OK) {
            const DWRITE_TRIMMING trimming{DWRITE_TRIMMING_GRANULARITY_CHARACTER, 0, 0};
            slot->SetTrimming(&trimming, ellipsis.Get());
        }
    }
}

// ---------------------------------------------------------------------------
// Canvas
// ---------------------------------------------------------------------------
Canvas::Canvas(ID2D1RenderTarget& target, const Fonts& fonts) : rt_(target), fonts_(fonts) {}

ID2D1SolidColorBrush* Canvas::Brush(D2D1_COLOR_F c) {
    if (!brush_) rt_.CreateSolidColorBrush(c, brush_.GetAddressOf());
    else brush_->SetColor(c);
    return brush_.Get();
}

void Canvas::Clear(D2D1_COLOR_F c) { rt_.Clear(c); }

void Canvas::Fill(const D2D1_RECT_F& r, D2D1_COLOR_F c, float radius) {
    if (r.right <= r.left || r.bottom <= r.top) return;
    if (radius > 0.0f) rt_.FillRoundedRectangle(D2D1::RoundedRect(r, radius, radius), Brush(c));
    else rt_.FillRectangle(r, Brush(c));
}

void Canvas::Stroke(const D2D1_RECT_F& r, D2D1_COLOR_F c, float radius, float width) {
    const D2D1_RECT_F in = Inset(r, width * 0.5f, width * 0.5f);
    if (in.right <= in.left || in.bottom <= in.top) return;
    if (radius > 0.0f) rt_.DrawRoundedRectangle(D2D1::RoundedRect(in, radius, radius), Brush(c), width);
    else rt_.DrawRectangle(in, Brush(c), width);
}

void Canvas::Line(D2D1_POINT_2F a, D2D1_POINT_2F b, D2D1_COLOR_F c, float width) {
    rt_.DrawLine(a, b, Brush(c), width);
}

void Canvas::Circle(D2D1_POINT_2F center, float radius, D2D1_COLOR_F c) {
    rt_.FillEllipse(D2D1::Ellipse(center, radius, radius), Brush(c));
}

void Canvas::Text(std::wstring_view text, const D2D1_RECT_F& r, Font font, D2D1_COLOR_F c, Align align) {
    IDWriteTextFormat* format = fonts_[font];
    if (!format || text.empty() || r.right <= r.left) return;
    format->SetTextAlignment(
        align == Align::Center ? DWRITE_TEXT_ALIGNMENT_CENTER
        : align == Align::Right ? DWRITE_TEXT_ALIGNMENT_TRAILING
                                : DWRITE_TEXT_ALIGNMENT_LEADING);
    rt_.DrawText(text.data(), static_cast<UINT32>(text.size()), format, r, Brush(c), D2D1_DRAW_TEXT_OPTIONS_CLIP);
}

float TextWidth(const Fonts& fonts, Font font, std::wstring_view text) {
    auto* dw = Graphics::Get().DWrite();
    IDWriteTextFormat* format = fonts[font];
    if (!dw || !format || text.empty()) return 0.0f;
    ComPtr<IDWriteTextLayout> layout;
    if (FAILED(dw->CreateTextLayout(text.data(), static_cast<UINT32>(text.size()), format, 1.0e6f, 1.0e6f,
                                    layout.GetAddressOf())))
        return 0.0f;
    DWRITE_TEXT_METRICS m{};
    if (FAILED(layout->GetMetrics(&m))) return 0.0f;
    return m.widthIncludingTrailingWhitespace;
}

void PaintD2D(HDC dc, const RECT& rect, const Fonts& fonts, const std::function<void(Canvas&)>& draw) {
    const int width = rect.right - rect.left;
    const int height = rect.bottom - rect.top;
    if (width <= 0 || height <= 0) return;

    auto& g = Graphics::Get();
    HDC buffer = g.Buffer(width, height);
    ID2D1DCRenderTarget* target = g.Target();
    if (!buffer || !target) return;

    const RECT local{0, 0, width, height};
    if (FAILED(target->BindDC(buffer, &local))) return;
    target->BeginDraw();
    target->SetTransform(D2D1::Matrix3x2F::Translation(static_cast<float>(-rect.left), static_cast<float>(-rect.top)));
    target->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
    {
        Canvas canvas(*target, fonts);
        draw(canvas);
    }
    if (target->EndDraw() == D2DERR_RECREATE_TARGET) g.ResetTarget();
    ::BitBlt(dc, rect.left, rect.top, width, height, buffer, 0, 0, SRCCOPY);
}

void ApplyBackdrop(HWND window, bool dark_mode, MARGINS margins) {
    const BOOL dark = dark_mode ? TRUE : FALSE;
    ::DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

    HIGHCONTRASTW contrast{sizeof(contrast)};
    const bool high_contrast = ::SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(contrast), &contrast, 0) &&
                               (contrast.dwFlags & HCF_HIGHCONTRASTON);

    auto& g = Graphics::Get();
    const DWORD backdrop = high_contrast ? 1u /* DWMSBT_NONE */ : 2u /* DWMSBT_MAINWINDOW (Mica) */;
    g.mica = SUCCEEDED(::DwmSetWindowAttribute(window, DWMWA_SYSTEMBACKDROP_TYPE, &backdrop, sizeof(backdrop))) && !high_contrast;

    const MARGINS applied = g.mica ? margins : MARGINS{0, 0, 0, 0};
    ::DwmExtendFrameIntoClientArea(window, &applied);

    if (!g.mica) {
        const COLORREF caption = ToColorRef(Palette::For(dark_mode).opaque_base);
        ::DwmSetWindowAttribute(window, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
    }
}

} // namespace KvcForensic::ui
