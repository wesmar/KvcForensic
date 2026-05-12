#include "analysis/report_builder.h"
#include "cli/credential_pipeline.h"
#include "core/module_index.h"
#include "core/text_utils.h"
#include "core/virtual_memory.h"
#include "lsa/template_registry.h"
#include "minidump/minidump_parser.h"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace kvc {
namespace {

std::string hex64(std::uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << v;
    return ss.str();
}

void print_info(const minidump::DumpMetadata& d) {
    std::cout << "path: " << d.path.string() << '\n';
    std::cout << "size: " << d.file_size << '\n';
    std::cout << "signature: " << hex64(d.header.signature) << '\n';
    std::cout << "version: " << d.header.version << '\n';
    std::cout << "streams: " << d.header.stream_count << '\n';
    std::cout << "stream_directory_rva: " << hex64(d.header.stream_directory_rva) << '\n';
    std::cout << "timestamp: " << d.header.timestamp << '\n';
    std::cout << "flags: " << hex64(d.header.flags) << '\n';
    if (d.system_info) {
        std::cout << "os_version: " << d.system_info->major << '.' << d.system_info->minor
                  << " build " << d.system_info->build << '\n';
        std::cout << "processor_architecture: " << d.system_info->processor_architecture << '\n';
    }
    std::cout << "modules: " << d.modules.size() << '\n';
    std::cout << "memory64_ranges: " << d.memory64_descriptor_count << '\n';
    std::cout << "memory64_resident: " << d.memory_ranges.size() << '\n';
    if (d.memory64_skipped_descriptors > 0)
        std::cout << "memory64_skipped: " << d.memory64_skipped_descriptors << '\n';
    std::cout << "memory64_total_bytes: " << d.memory64_total_bytes << '\n';
    std::cout << "thread_count: " << d.thread_count << '\n';
    std::cout << "thread_ex_count: " << d.thread_ex_count << '\n';
    std::cout << "memory_list_count: " << d.memory_list_count << '\n';
    std::cout << "memory_info_entries: " << d.memory_info_entry_count << '\n';
    std::cout << "handle_descriptors: " << d.handle_descriptor_count << '\n';
    std::cout << "unloaded_modules: " << d.unloaded_module_count << '\n';
}

void print_streams(const minidump::DumpMetadata& d) {
    for (const auto& s : d.streams) {
        std::cout << std::left << std::setw(28) << minidump::stream_type_name(s.type)
                  << " type=" << std::setw(3) << s.type
                  << " rva=" << hex64(s.rva)
                  << " size=" << s.size << '\n';
    }
}

void print_modules(const minidump::DumpMetadata& d) {
    for (const auto& m : d.modules) {
        std::cout << hex64(m.base_address)
                  << " size=" << std::setw(8) << m.size
                  << " " << m.name << '\n';
    }
}

void print_memory_map(const minidump::DumpMetadata& d) {
    for (const auto& r : d.memory_ranges) {
        std::cout << hex64(r.virtual_address)
                  << " size=" << std::setw(10) << r.size
                  << " file_rva=" << hex64(r.file_rva) << '\n';
    }
}

void print_slices(const core::ModuleIndex& mi) {
    static const char* kInteresting[] = {
        "lsasrv.dll", "msv1_0.dll", "wdigest.dll", "kerberos.dll",
        "dpapisrv.dll", "tspkg.dll", "livessp.dll", "cloudap.dll",
        "schannel.dll", "ntdll.dll",
    };
    for (const auto* name : kInteresting) {
        const auto* ms = mi.find(name);
        if (!ms) continue;
        std::cout << name << " base=" << hex64(ms->module->base_address)
                  << " size=" << ms->module->size
                  << " resident=" << ms->total_resident_bytes
                  << " slices=" << ms->slices.size() << '\n';
        for (const auto& s : ms->slices) {
            std::cout << "  va=" << hex64(s.va)
                      << " rva=" << hex64(s.rva)
                      << " size=" << s.size << '\n';
        }
    }
}

void print_templates(const lsa::templates::TemplateRegistry& reg,
                     const minidump::DumpMetadata& d) {
    std::cout << "templates_loaded: " << reg.total_count() << '\n';
    std::cout << "  msv:         " << reg.msv_all().size() << '\n';
    std::cout << "  wdigest:     " << reg.wdigest_all().size() << '\n';
    std::cout << "  kerberos:    " << reg.kerberos_all().size() << '\n';
    std::cout << "  dpapi:       " << reg.dpapi_all().size() << '\n';
    std::cout << "  lsa_secrets: " << reg.lsa_secrets_all().size() << '\n';
    std::cout << "  tspkg:       " << reg.tspkg_all().size() << '\n';
    if (!d.system_info) {
        std::cout << "build: unknown (no SystemInfoStream)\n";
        return;
    }
    const auto build = d.system_info->build;
    std::cout << "build: " << build << '\n';
    auto report = [&](const char* what, const auto* spec) {
        std::cout << "  " << what << ": "
                  << (spec ? spec->name : std::string("<none>")) << '\n';
    };
    report("msv     ", reg.select_msv(build));
    report("wdigest ", reg.select_wdigest(build));
    report("kerberos", reg.select_kerberos(build));
    report("dpapi   ", reg.select_dpapi(build));
    report("secrets ", reg.select_lsa_secrets(build));
    report("tspkg   ", reg.select_tspkg(build));
}

struct AnalyzeOptions {
    std::filesystem::path input = "lsass.dmp";
    std::filesystem::path output = "output_KvcForensic.txt";
    std::filesystem::path templates;
    std::string format = "txt";
    bool full = false;
    bool reveal_secrets = false;
};

AnalyzeOptions parse_analyze_options(int argc, char** argv) {
    AnalyzeOptions o{};
    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        auto need_value = [&](std::string_view name) -> const char* {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + std::string(name));
            return argv[++i];
        };
        if (arg == "--input") o.input = need_value(arg);
        else if (arg == "--output") o.output = need_value(arg);
        else if (arg == "--templates") o.templates = need_value(arg);
        else if (arg == "--format") {
            o.format = need_value(arg);
            if (o.format != "txt" && o.format != "json" && o.format != "both")
                throw std::runtime_error("invalid --format value");
        }
        else if (arg == "--full") o.full = true;
        else if (arg == "--reveal-secrets" || arg == "--unsafe-output") o.reveal_secrets = true;
        else if (arg == "--force") {}
        else if (arg == "--compare") (void)need_value(arg);
        else if (arg == "--export-tickets") (void)need_value(arg);
        else throw std::runtime_error("unknown analyze argument: " + std::string(arg));
    }
    return o;
}

void print_usage(std::ostream& out) {
    out << "usage: KvcForensic <command> <dump.dmp>\n\n"
        << "analyze mode:\n"
        << "  KvcForensic --analyze-dump --input <file> [--output <file>]\n"
        << "             [--templates <path>] [--format txt|json|both]\n"
        << "             [--full] [--reveal-secrets]\n\n"
        << "commands:\n"
        << "  info             minidump header and summary\n"
        << "  streams          list minidump streams\n"
        << "  modules          list loaded modules\n"
        << "  memory-map       list Memory64ListStream ranges\n"
        << "  slices           module x memory intersections\n"
        << "  templates        loaded JSON templates and best match for dump build\n"
        << "  credentials      full credential pipeline (sessions, hashes, masterkeys)\n"
        << "                   add --reveal-secrets to print key material in clear\n";
}

std::filesystem::path templates_for_inspection(int argc, char** argv,
                                               const std::filesystem::path& argv0) {
    std::filesystem::path explicit_path;
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string_view(argv[i]) == "--templates") {
            explicit_path = argv[i + 1];
            break;
        }
    }
    return cli::resolve_template_path(explicit_path, argv0);
}

int run_analyze_mode(int argc, char** argv) {
    const auto options = parse_analyze_options(argc, argv);
    const std::filesystem::path argv0 = argc > 0 ? std::filesystem::path(argv[0]) : "";
    const auto tmpl_path = cli::resolve_template_path(options.templates, argv0);

    minidump::MinidumpParser parser;
    const auto dump = parser.parse(options.input);

    core::VirtualMemory vmem(dump.file_bytes(), dump.memory_ranges);
    core::ModuleIndex modules(dump, vmem);

    lsa::templates::TemplateRegistry registry;
    bool templates_ok = false;
    if (!tmpl_path.empty()) {
        templates_ok = registry.load(tmpl_path);
        if (!templates_ok) {
            std::cerr << "warning: template load failed (" << tmpl_path.string()
                      << "): " << registry.last_error() << '\n';
        }
    } else {
        std::cerr << "warning: KvcForensic.json not found; templates not loaded\n";
    }

    analysis::AnalysisResult result;
    if (templates_ok) {
        cli::CredentialPipeline pipe(dump, vmem, modules, registry);
        result = pipe.run();
    } else {
        result.metadata = dump;
        result.secrets_extractor_error = "templates not loaded";
    }

    analysis::ReportOptions ropt{options.full, options.reveal_secrets};

    if (options.format == "txt" || options.format == "both") {
        analysis::write_text_file(options.output,
            analysis::ReportBuilder::build_text(result, ropt));
        std::cout << "wrote: " << options.output.string() << '\n';
    }
    if (options.format == "json" || options.format == "both") {
        auto json_path = options.format == "json" ? options.output : options.output;
        if (options.format == "both") json_path.replace_extension(".json");
        analysis::write_text_file(json_path, analysis::ReportBuilder::build_json(result, ropt));
        std::cout << "wrote: " << json_path.string() << '\n';
    }
    if (!options.reveal_secrets) {
        std::cout << "note: secret material redacted; rerun with --reveal-secrets to print clear-text\n";
    }
    return 0;
}

int run(int argc, char** argv) {
    if (argc >= 2) {
        const std::string_view first = argv[1];
        if (first == "--help" || first == "-h" || first == "/?") {
            print_usage(std::cout);
            return 0;
        }
        if (first == "--analyze-dump") return run_analyze_mode(argc, argv);
    }

    if (argc < 3) {
        print_usage(argc == 1 ? std::cout : std::cerr);
        return argc == 1 ? 0 : 2;
    }

    const std::string_view cmd = argv[1];
    const std::filesystem::path argv0 = argc > 0 ? std::filesystem::path(argv[0]) : "";

    // Allow `<cmd> [--templates <path>] [--reveal-secrets] <dump>` in any order.
    std::filesystem::path dump_path;
    bool reveal_secrets = false;
    for (int i = 2; i < argc; ++i) {
        std::string_view a = argv[i];
        if (a == "--templates") {
            if (i + 1 >= argc) throw std::runtime_error("missing --templates value");
            ++i;
            continue;
        }
        if (a == "--reveal-secrets" || a == "--unsafe-output") { reveal_secrets = true; continue; }
        if (!a.empty() && a.front() == '-') continue;
        dump_path = a;
        break;
    }
    if (dump_path.empty()) {
        std::cerr << "error: dump path missing\n";
        return 2;
    }

    minidump::MinidumpParser parser;
    const auto dump = parser.parse(dump_path);

    if (cmd == "info") { print_info(dump); return 0; }
    if (cmd == "streams") { print_streams(dump); return 0; }
    if (cmd == "modules") { print_modules(dump); return 0; }
    if (cmd == "memory-map") { print_memory_map(dump); return 0; }

    core::VirtualMemory vmem(dump.file_bytes(), dump.memory_ranges);
    core::ModuleIndex modules(dump, vmem);

    if (cmd == "slices") { print_slices(modules); return 0; }

    if (cmd == "templates" || cmd == "credentials") {
        const auto tmpl_path = templates_for_inspection(argc, argv, argv0);
        lsa::templates::TemplateRegistry registry;
        bool ok = false;
        if (!tmpl_path.empty()) {
            ok = registry.load(tmpl_path);
            if (!ok) std::cerr << "warning: template load: " << registry.last_error() << '\n';
        } else {
            std::cerr << "warning: KvcForensic.json not found\n";
        }
        if (cmd == "templates") {
            if (ok) print_templates(registry, dump);
            return ok ? 0 : 1;
        }
        if (!ok) return 1;
        cli::CredentialPipeline pipe(dump, vmem, modules, registry);
        const auto result = pipe.run();
        analysis::ReportOptions ropt{false, reveal_secrets};
        std::cout << analysis::ReportBuilder::build_text(result, ropt);
        if (!reveal_secrets) {
            std::cout << "note: secret material redacted; pass --reveal-secrets to print clear-text\n";
        }
        return 0;
    }

    print_usage(std::cerr);
    return 2;
}

} // namespace
} // namespace kvc

int main(int argc, char** argv) {
    try {
        return kvc::run(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << '\n';
        return 1;
    }
}
