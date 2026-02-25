#include "lsa/TemplateRegistry.h"
#include "KvcForensicWindow.h"
#include "WindowsBuildInfo.h"
#include "analysis/JsonReportBuilder.h"
#include "analysis/SafeAnalysisReport.h"
#include "analysis/TextReportBuilder.h"
#include "security/TrustedInstaller.h"

#include <Windows.h>
#include <shellapi.h>
#include <stdio.h>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace {

enum class OutputFormat {
    Txt,
    Json,
    Both
};

struct CliOptions {
    bool batch_mode = false;
    bool force_mode = false;
    bool full_report = false;
    std::wstring input_path = L"lsass.dmp";
    std::wstring output_path = L"output_KvcForensic.txt";
    OutputFormat format = OutputFormat::Txt;
    std::optional<std::wstring> compare_path;

    bool cli_mode = false;
    std::wstring cli_command;
};

struct CliParseResult {
    CliOptions options{};
    bool show_help = false;
    int help_exit_code = 0;
    std::wstring error_message;
};

std::wstring BuildPathInCwd(const std::wstring& filename) {
    const std::filesystem::path cwd = std::filesystem::current_path();
    return (cwd / std::filesystem::path(filename)).wstring();
}

std::wstring ReplaceExtension(const std::wstring& path, const wchar_t* ext) {
    std::filesystem::path p(path);
    p.replace_extension(ext);
    return p.wstring();
}

OutputFormat ParseFormat(const std::wstring& value) {
    if (_wcsicmp(value.c_str(), L"txt") == 0) {
        return OutputFormat::Txt;
    }
    if (_wcsicmp(value.c_str(), L"json") == 0) {
        return OutputFormat::Json;
    }
    if (_wcsicmp(value.c_str(), L"both") == 0) {
        return OutputFormat::Both;
    }
    return static_cast<OutputFormat>(-1);
}

std::wstring BuildCliHelp() {
    return
        L"KvcForensic CLI usage:\n"
        L"  KvcForensic.exe --analyze-dump [--input <file>] [--output <file>] [--format txt|json|both] [--compare <file>] [--force] [--full]\n"
        L"  KvcForensic.exe --cli <command>\n"
        L"  KvcForensic.exe -cli <command>\n"
        L"  KvcForensic.exe --help\n\n"
        L"Options:\n"
        L"  --full    Include metadata header (dump header/streams/modules/security) in TXT output.\n"
        L"            Default: credentials only (FILE: header + logon sessions).\n\n"
        L"Examples:\n"
        L"  KvcForensic.exe --analyze-dump --input dump.dmp --format both\n"
        L"  KvcForensic.exe --analyze-dump --input lsass.dmp --output output.txt --full\n"
        L"  KvcForensic.exe --analyze-dump --input dump.dmp --format both --compare ref.txt --force\n"
        L"  KvcForensic.exe --cli \"whoami /all\"\n";
}

CliParseResult ParseCli(const int argc, wchar_t** argv) {
    CliParseResult result{};
    CliOptions& options = result.options;
    std::vector<std::wstring> tokens;
    bool explicit_batch_flag = false;

    // Normal case: argv is already split.
    for (int i = 1; i < argc; ++i) {
        tokens.emplace_back(argv[i]);
    }

    // Fallback for launchers that pass all args as a single string token.
    if (tokens.size() == 1 && tokens[0].find(L"--") != std::wstring::npos && tokens[0].find(L' ') != std::wstring::npos) {
        const std::wstring synthetic = L"dummy " + tokens[0];
        int split_argc = 0;
        wchar_t** split_argv = ::CommandLineToArgvW(synthetic.c_str(), &split_argc);
        if (split_argv != nullptr) {
            if (split_argc > 1) {
                std::vector<std::wstring> recovered;
                recovered.reserve(static_cast<std::size_t>(split_argc - 1));
                for (int i = 1; i < split_argc; ++i) {
                    recovered.emplace_back(split_argv[i]);
                }
                tokens = std::move(recovered);
            }
            ::LocalFree(split_argv);
        }
    }

    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const std::wstring arg = tokens[i];
        if (_wcsicmp(arg.c_str(), L"--help") == 0 || _wcsicmp(arg.c_str(), L"-h") == 0 || _wcsicmp(arg.c_str(), L"/?") == 0) {
            result.show_help = true;
            result.help_exit_code = 0;
            return result;
        }
        if ((_wcsicmp(arg.c_str(), L"-cli") == 0 || _wcsicmp(arg.c_str(), L"--cli") == 0) &&
            i + 1 < tokens.size()) {
            options.cli_mode = true;
            options.cli_command = tokens[++i];
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--analyze-dump") == 0) {
            explicit_batch_flag = true;
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--input") == 0 && i + 1 < tokens.size()) {
            options.input_path = tokens[++i];
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--output") == 0 && i + 1 < tokens.size()) {
            options.output_path = tokens[++i];
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--format") == 0 && i + 1 < tokens.size()) {
            const OutputFormat parsed = ParseFormat(tokens[++i]);
            if (parsed == static_cast<OutputFormat>(-1)) {
                result.show_help = true;
                result.help_exit_code = 2;
                result.error_message = L"Invalid value for --format. Use: txt, json, both.";
                return result;
            }
            options.format = parsed;
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--compare") == 0 && i + 1 < tokens.size()) {
            options.compare_path = tokens[++i];
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--force") == 0 || _wcsicmp(arg.c_str(), L"-force") == 0) {
            options.force_mode = true;
            continue;
        }
        if (_wcsicmp(arg.c_str(), L"--full") == 0) {
            options.full_report = true;
            continue;
        }
        result.show_help = true;
        result.help_exit_code = 2;
        result.error_message = L"Unknown or incomplete argument: " + arg;
        return result;
    }
    const bool has_batch_options =
        options.force_mode ||
        (options.input_path != L"lsass.dmp") ||
        (options.output_path != L"output_KvcForensic.txt") ||
        (options.format != OutputFormat::Txt) ||
        options.compare_path.has_value();

    options.batch_mode = explicit_batch_flag || has_batch_options;
    return result;
}

bool InitializeConsole() {
    if (::AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);
        return true;
    }
    return false;
}

[[noreturn]] void ExitNow(const int code) {
    // Nudge cmd.exe to redraw prompt immediately (no manual Enter needed).
    HANDLE hIn = ::GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != nullptr && hIn != INVALID_HANDLE_VALUE) {
        INPUT_RECORD ir[2]{};
        ir[0].EventType = KEY_EVENT;
        ir[0].Event.KeyEvent.bKeyDown = TRUE;
        ir[0].Event.KeyEvent.wRepeatCount = 1;
        ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
        ir[0].Event.KeyEvent.wVirtualScanCode = 0x1C;
        ir[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';
        ir[1] = ir[0];
        ir[1].Event.KeyEvent.bKeyDown = FALSE;
        DWORD written = 0;
        ::WriteConsoleInputW(hIn, ir, 2, &written);
    }

    fflush(stdout);
    fflush(stderr);
    ::FreeConsole();
    ::ExitProcess(static_cast<UINT>(code));
}

int RunDumpAnalysisMode(const CliOptions& options) {
    const std::wstring input_path = BuildPathInCwd(options.input_path);
    const std::wstring txt_output = BuildPathInCwd(options.output_path);
    const std::wstring json_output = ReplaceExtension(txt_output, L".json");
    const std::wstring compare_output = ReplaceExtension(txt_output, L".compare.txt");

    KvcForensic::analysis::SafeAnalysisEngine engine;
    std::optional<std::uint32_t> forced_build = std::nullopt;
    if (options.force_mode) {
        const auto os = KvcForensic::platform::QueryOsBuild();
        if (os.ok && os.build > 0) {
            forced_build = os.build;
        }
    }
    const auto report = engine.AnalyzeFile(input_path, forced_build);

    if (options.format == OutputFormat::Txt || options.format == OutputFormat::Both) {
        std::wstring text = options.full_report
            ? KvcForensic::analysis::BuildFullTextReport(report)
            : KvcForensic::analysis::BuildTextReport(report);
        if (options.compare_path.has_value()) {
            const auto compare_path = BuildPathInCwd(options.compare_path.value());
            const auto comparison = KvcForensic::analysis::BuildReferenceComparison(report, compare_path);
            text.append(L"\r\n\r\n");
            text.append(comparison);
            (void)KvcForensic::analysis::WriteUtf8File(compare_output, comparison, nullptr);
        }
        if (!KvcForensic::analysis::WriteUtf8File(txt_output, text, nullptr)) {
            return 2;
        }
    }

    if (options.format == OutputFormat::Json || options.format == OutputFormat::Both) {
        const auto json = KvcForensic::analysis::BuildJsonReport(report);
        const auto target = (options.format == OutputFormat::Json) ? txt_output : json_output;
        if (!KvcForensic::analysis::WriteUtf8File(target, json, nullptr)) {
            return 3;
        }
    }

    return report.dump.valid ? 0 : 4;
}

} // namespace

int WINAPI wWinMain(
    HINSTANCE hInstance,
    HINSTANCE,
    PWSTR,
    int nCmdShow) {
    int argc = 0;
    wchar_t** argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    CliParseResult parse_result = (argv != nullptr) ? ParseCli(argc, argv) : CliParseResult{};
    CliOptions options = parse_result.options;
    if (argv != nullptr) {
        ::LocalFree(argv);
    }

    if (parse_result.show_help) {
        InitializeConsole();
        if (!parse_result.error_message.empty()) {
            wprintf(L"Error: %s\n\n", parse_result.error_message.c_str());
        }
        wprintf(L"%s", BuildCliHelp().c_str());
        ExitNow(parse_result.help_exit_code);
    }

    if (options.cli_mode) {
        InitializeConsole();
        wprintf(L"[+] Dual-Head CLI Mode initialized.\n");
        wprintf(L"[+] Running command as TrustedInstaller: %s\n", options.cli_command.c_str());
        if (KvcForensic::security::TrustedInstaller::RunCommand(options.cli_command)) {
            wprintf(L"[+] Command executed successfully.\n");
            ExitNow(0);
        }
        wprintf(L"[-] Failed to execute command.\n");
        ExitNow(1);
    }

    std::wstring template_error;
    wchar_t exePath[MAX_PATH] = {};
    if (!::GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        template_error = L"Cannot resolve executable path for template lookup.";
    } else {
        std::filesystem::path p(exePath);
        std::filesystem::path jsonPath = p.parent_path() / "KvcForensic.json";
        if (!KvcForensic::lsa::templates::InitializeRegistry(jsonPath.wstring())) {
            template_error = KvcForensic::lsa::templates::GetRegistryInitError();
            if (template_error.empty()) {
                template_error = L"Template initialization failed.";
            }
        }
    }

    if (!template_error.empty()) {
        if (options.batch_mode) {
            InitializeConsole();
            wprintf(L"Template initialization error: %s\n", template_error.c_str());
            ExitNow(5);
        }
        ::MessageBoxW(nullptr, template_error.c_str(), L"KvcForensic - Template Error", MB_ICONERROR | MB_OK);
        return 2;
    }

    if (options.batch_mode) {
        InitializeConsole();
        int res = RunDumpAnalysisMode(options);
        if (res == 0) {
            wprintf(L"Done!. Results written successfully. Check output file(s) for details.\n");
        } else {
            wprintf(L"Done!. Analysis failed. Check logs and file paths.\n");
        }
        ExitNow(res);
    }

    KvcForensic::ui::KvcForensicWindow app;
    if (!app.Create(hInstance, nCmdShow)) {
        ::MessageBoxW(nullptr, L"Failed to create main window.", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    return app.RunMessageLoop();
}
