#pragma once

#include <Windows.h>
#include <commctrl.h>

#include "analysis/SafeAnalysisReport.h"

#include <atomic>
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
    LRESULT HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void CreateControls(HWND hwnd);
    void CreateAppMenu();
    void LayoutControls(int width, int height);

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
    HWND   status_bar_ = nullptr;
    HMENU  view_menu_  = nullptr;
    HACCEL accel_      = nullptr;
    HFONT  font_       = nullptr;
    HBRUSH bg_brush_   = nullptr;
    HICON  icon_big_   = nullptr;
    HICON  icon_small_ = nullptr;

    int  splitter_x_    = 260;
    bool splitter_drag_ = false;

    bool is_dark_mode_ = false;
    bool show_all_accounts_ = false;

    analysis::SafeAnalysisReport report_;
    bool has_report_ = false;

    std::thread           analysis_thread_;
    std::atomic<bool>     analyzing_{ false };
    std::wstring          loaded_path_;
};

} // namespace KvcForensic::ui
