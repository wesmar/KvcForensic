#pragma once

#include <Windows.h>
#include <commctrl.h>

#include "analysis/SafeAnalysisReport.h"
#include "ui/D2DTheme.h"
#include "ui/MenuBar.h"

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace KvcForensic::ui {

// Tree node type, encoded in high 16 bits of LPARAM
enum class NodeType : UINT16 {
    Root        = 0,
    Info        = 1,
    Modules     = 2,
    Module      = 3,
    Streams     = 4,
    Stream      = 5,
    Credentials = 6,
    Session     = 7,
    Msv         = 8,
    WDigest     = 9,
    CredMan     = 10,
    Kerberos    = 11,
    Dpapi       = 12,
};

class KvcForensicWindow {
public:
    bool Create(HINSTANCE instance, int nCmdShow);
    int  RunMessageLoop();

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK DetailSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                               UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
    LRESULT HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleHeaderCustomDraw(NMCUSTOMDRAW* cd);
    LRESULT HandleListCustomDraw(NMLVCUSTOMDRAW* cd);

    void CreateControls(HWND hwnd);
    void CreateAppMenu();
    void RecreateFonts(UINT dpi);
    void LayoutControls(int width, int height);
    void PaintWindow(HDC hdc);
    void InvalidateMenuBar();
    void InvalidateStatusBar();
    void RestoreWindowState();
    void SaveWindowState() const;

    void OpenDumpDialog();
    void LoadDump(const std::wstring& path);
    void OnAnalysisDone(analysis::SafeAnalysisReport* result);

    void PopulateTree();
    void ClearDetail();
    void ShowNodeDetail(LPARAM node_param);
    void AddDetailRow(const wchar_t* prop, const wchar_t* value);
    void AddDetailRow(const wchar_t* prop, const std::wstring& value);
    void SetStatus(int part, const wchar_t* text);
    void SetStatusWarningMode(bool warning);

    void ApplyTheme();
    void UpdateTheme();
    void CopySelectedRows();

    // Node LPARAM encoding: high 16 bits = NodeType, low 16 bits = index
    static LPARAM    EncodeNode(NodeType type, int idx = 0);
    static NodeType  GetNodeType(LPARAM p);
    static int       GetNodeIndex(LPARAM p);

    HINSTANCE hInstance_  = nullptr;
    HWND   hwnd_       = nullptr;
    HWND   tree_       = nullptr;
    HWND   detail_     = nullptr;
    HMENU  file_menu_  = nullptr;
    HMENU  view_menu_  = nullptr;
    HMENU  context_menu_ = nullptr;
    HACCEL accel_      = nullptr;
    HFONT  font_       = nullptr;
    HPEN   grid_pen_   = nullptr;
    HICON  icon_big_   = nullptr;
    HICON  icon_small_ = nullptr;

    Fonts  fonts_;
    std::unique_ptr<MenuBar> menu_bar_;
    UINT   dpi_           = 96;
    bool   tracking_mouse_ = false;
    int    initial_show_cmd_ = SW_SHOWNORMAL;

    int  splitter_x_    = 280;
    bool splitter_drag_ = false;

    bool is_dark_mode_      = false;
    bool show_all_accounts_ = false;
    bool status_warning_    = false;
    std::array<std::wstring, 3> status_text_;

    analysis::SafeAnalysisReport report_;
    bool has_report_ = false;

    std::thread           analysis_thread_;
    std::atomic<bool>     analyzing_{ false };
    std::wstring          loaded_path_;
};

} // namespace KvcForensic::ui
