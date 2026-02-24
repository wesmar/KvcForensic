# KvcForensic

![KvcForensic](images/KvcForensic.jpg)

Modern Windows LSA credential parser for `lsass.dmp` minidumps.
Primary targets: **Windows 11 24H2 / 25H2** (builds 26100+) and their Server equivalents (Windows Server 2025). Older build templates are present but are not actively maintained.

Built entirely on pure Win32 API. No runtime dependencies beyond the OS and the BCrypt primitive. No DbgHelp, no third-party libraries, no framework.

Binary size is under 300 KB when linked against the system CRT, and under 600 KB with the CRT statically embedded.

---

## What it does

Parses a full-memory `lsass.dmp` minidump and extracts credentials from the following security packages:

| Package    | Extracted data                                          |
|------------|---------------------------------------------------------|
| MSV1_0     | NT hash, LM hash, SHA1, DPAPI blob                     |
| WDigest    | Cleartext password (when available)                     |
| Kerberos   | Username, domain, cleartext password, ticket list       |
| CredMan    | Credential Manager stored entries                       |
| DPAPI      | MasterKey cache entries, decrypted masterkey, SHA1      |

Output formats: plain text report and/or structured JSON.

---

## Obtaining the dump

Standard tools (ProcDump, comsvcs.dll rundll32) fail against lsass.exe on modern Windows due to PPL (Protected Process Light) enforcement. To obtain a full-memory dump on Windows 11 24H2/25H2 with PPL active, use [kvc](https://github.com/wesmar/kvc), which bypasses PPL via kernel-level process protection manipulation:

```
kvc.exe dump lsass
```

The dump is written to the current user's Downloads folder by default. Pass it directly to KvcForensic:

```
KvcForensic.exe --analyze-dump --input "%USERPROFILE%\Downloads\lsass.dmp" --output result.txt --format both
```

---

## Architecture

### Memory model

The dump file is memory-mapped once via `CreateFileMappingW` / `MapViewOfFile` and exposed internally as a `std::span<const std::byte>`. Every subsequent read is a direct `memcpy` from a precomputed file offset. There is no `ReadFile`, no seeking, no intermediate heap allocation per read. `VirtualMemory::VaToRva()` translates virtual addresses from the dump's `Memory64ListStream` descriptors into file offsets by scanning the range table, which in practice resolves in a small number of comparisons per access.

```
lsass.dmp  ->  MapViewOfFile  ->  span<byte>
                                      |
                           VirtualMemory::VaToRva()
                                      |
                                memcpy to caller
```

### Minidump parsing

The minidump format is parsed from scratch using only the public MINIDUMP_* structure definitions from the Windows SDK. DbgHelp is not used at any point. Stream discovery, module enumeration, and Memory64ListStream range building are all implemented directly. The build number read from `SystemInfoStream` drives template selection for every subsequent parsing step.

### Cryptography

LSA encrypts in-memory credentials using either AES-CFB128 or 3DES-CBC, selected by a simple rule: if the encrypted blob length is not divisible by 8, AES is used; otherwise 3DES. This matches the logic observed in pypykatz.

The Windows BCrypt API exposes CFB only in 8-bit feedback (CFB8) mode. CFB128 is not available natively. KvcForensic implements CFB128 manually on top of `BCryptEncrypt` in ECB mode: the counter block is encrypted to produce a keystream block, which is XOR-ed with 16 bytes of ciphertext, then the counter is updated with those 16 ciphertext bytes before the next block. This matches the LSA behavior precisely.

3DES-CBC uses only the first 8 bytes of the IV.

Key material (AES-128/256, 3DES, IV) is located by scanning `lsasrv.dll` for the `LSA_x64_9` signature (a 16-byte byte pattern specific to Windows 11 24H2+) and following the `KIWI_BCRYPT_HANDLE_KEY` -> `KIWI_BCRYPT_KEY81` pointer chain to the raw key bytes at a fixed structure offset.

### Template system

Each security package version is described by a `*TemplateSpec` structure containing:

- Build range (`min_build` / `max_build`)
- Byte signature to locate the data structure within the loaded DLL image in memory
- Offsets relative to the signature match

Templates are selected at runtime based on the build number extracted from `SystemInfoStream`. The MSV package covers 10 templates spanning Windows 7 (build 7600) through Windows 11 25H2 (build 26200+). WDigest has 2 templates, Kerberos 1, DPAPI 1.

For builds where `parser_support = true` (currently 24H2 and 25H2), session field offsets are taken directly from the template. Older builds fall back to `DetectSessionFieldLayout()`, which scores six candidate offset sets against actual memory content — checking LUID validity, string readability, and SID prefix — and selects the highest-scoring set.

The template definitions are compiled in as static C++ arrays. A planned future version will load templates from an external JSON file, allowing build coverage to be extended without recompilation. The template resolution logic and dereference chains will remain unchanged.

### MSV credential walk

```
FindMsvLogonList()        -- locate LogonSessionList via RIP-relative signature in lsasrv.dll
Walk()                    -- traverse doubly-linked list, one node per LogonSession
ExtractCredentials()      -- KIWI_MSV1_0_CREDENTIAL_LIST -> PRIMARY_CREDENTIAL_ENC
LsaSecretsExtractor       -- decrypt blob -> parse MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC
```

The decrypted `MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC` structure for 24H2/25H2 exists in two variants, distinguished by a format flag at offset 40. The flag reflects whether DPAPI protection is active for the credential:

**Format A** (isDPAPIProtected = 0):

| Offset | Field              | Size    |
|--------|--------------------|---------|
| +0     | LogonDomainName    | 16 B    |
| +16    | UserName           | 16 B    |
| +40    | isDPAPIProtected   | 1 B     |
| +41    | isNtOwfPassword    | 1 B     |
| +43    | isShaOwfPassword   | 1 B     |
| +44    | isDPAPILimitedKey  | 1 B     |
| +50    | DPAPILimitedKey    | 20 B    |
| +70    | NtOwfPassword      | 16 B    |
| +86    | LmOwfPassword      | 16 B    |
| +102   | ShaOwfPassword     | 20 B    |

**Format B** (isDPAPIProtected = 1, NT hash relocated):

| Offset | Field              | Size    |
|--------|--------------------|---------|
| +50    | NtOwfPassword      | 16 B    |
| +102   | ShaOwfPassword     | 20 B    |
| +122   | DPAPILimitedKey    | 20 B    |

Both formats are handled transparently during extraction.

### Kerberos AVL walk

Kerberos stores sessions in an `RTL_AVL_TABLE`. The tree is traversed with an iterative DFS using an explicit `std::vector` stack rather than recursion, eliminating any risk of stack overflow on deep or corrupted trees. Visited nodes are tracked in a `std::set<uint64_t>`. For each node, the `OrderedPointer` field at node+32 yields the session pointer. The LUID is read at session+64; if that value does not match any known session LUID, a fallback probe over offsets {56, 48, 72, 40, 32} is performed.

Kerberos ticket lists (three lists per session at offsets +280, +304, +328 in `KIWI_KERBEROS_LOGON_SESSION_24H2`) are extracted per session. Ticket metadata includes service name, target name, client name, flags, encryption type, kvno, and raw ticket bytes.

### WDigest list walk

On some builds, WDigest maintains multiple adjacent list heads. KvcForensic probes four consecutive sentinel candidates to ensure complete coverage, deduplicating entries by virtual address so nodes reachable from multiple lists are not counted twice.

### DPAPI master key walk

The DPAPI signature `48 89 4F 08 48 89 78 08` appears multiple times in `lsasrv.dll`. KvcForensic collects all occurrences in `lsasrv.dll`, `dpapisrv.dll`, and `lsass.exe` (with a full-memory fallback if no module match is found), resolves each RIP-relative pointer to a `KIWI_MASTERKEY_CACHE_ENTRY` sentinel, and walks every distinct list. A global `visited_entries` set prevents double-processing of nodes reachable from multiple sentinels. Decrypted master keys are SHA1-hashed via BCrypt and included in the output.

### Credential Manager walk

CredMan entries are located via a pointer at session+0x168, which leads to a `KIWI_CREDMAN_SET_LIST_ENTRY` structure. The list is walked with a 255-entry safety limit. Usernames and server names are read from fixed offsets within each entry; passwords are decrypted using the same LSA key material as other packages.

---

## Design choices vs. mimikatz and pypykatz

After studying the source of both mimikatz and pypykatz, several design decisions were made differently:

**No DbgHelp dependency.** mimikatz relies on `MiniDumpReadDumpStream` and related DbgHelp APIs for minidump navigation. KvcForensic parses the MDMP format directly using only the public stream type definitions, eliminating the DbgHelp.dll dependency entirely.

**CFB128 implemented manually.** BCrypt on Windows exposes CFB only in 8-bit feedback mode. Both mimikatz and pypykatz work around this via a manual CFB128 loop. KvcForensic uses the same approach — ECB encrypt the counter, XOR with ciphertext, advance counter with ciphertext — but implemented over BCrypt's ECB primitive rather than a software AES implementation, keeping all cryptographic operations within the OS-provided boundary.

**Multiple DPAPI sentinel collection.** mimikatz and pypykatz typically follow the first matching signature occurrence to locate the DPAPI master key list. KvcForensic collects all occurrences across all relevant modules and walks every distinct list, using a global visited set to deduplicate. This accounts for cases where multiple code locations reference different list roots.

**Iterative Kerberos AVL traversal.** Recursive tree walks are straightforward to implement but can overflow on corrupted or adversarially constructed dumps. KvcForensic uses an explicit stack-based DFS, which behaves correctly regardless of tree depth.

**Two-format MSV credential layout.** The 24H2/25H2 primary credential structure exists in two distinct field arrangements depending on whether DPAPI protection is active. KvcForensic detects the format from the flag byte at offset 40 and parses each variant accordingly. Neither mimikatz (at the time of writing, targeting the single known layout) nor pypykatz explicitly branch on this flag.

**Scoring-based layout detection for older builds.** For builds without hardcoded offsets, KvcForensic evaluates six candidate session field layouts against actual dump content rather than maintaining a separate per-build offset table. Each candidate is scored by how many sessions yield a valid LUID, readable strings, and a recognizable SID prefix. The highest-scoring layout is used.

---

## CLI usage

```
KvcForensic.exe --analyze-dump [--input <file>] [--output <file>] [--format txt|json|both] [--compare <ref>] [--force] [--full]
KvcForensic.exe --cli "<command>"
KvcForensic.exe -cli "<command>"
KvcForensic.exe --help
```

**Options:**

`--input <file>` — path to the dump file (default: `lsass.dmp` in the current directory)

`--output <file>` — path for the text output (default: `output_KvcForensic.txt`). When `--format both` is used, the JSON output is written alongside with a `.json` extension derived from the text path.

`--format txt|json|both` — output format (default: `txt`)

`--compare <ref>` — compare extraction results against a previously generated text report. The diff is appended to the main output and also written to a `.compare.txt` file derived from the output path.

`--force` — override the build number embedded in the dump with the build number of the machine running KvcForensic. Useful when the dump was taken under a mismatched build or when the SystemInfoStream is unreliable.

`--full` — include full metadata in the text report: dump header, stream list, module list, and security package presence checks. Without this flag, output contains only the credential header and logon sessions.

`--help` / `-h` / `/?` — print usage and exit.

**Examples:**

```
# Analyze a dump, write both text and JSON output
KvcForensic.exe --analyze-dump --input lsass.dmp --format both

# Write a full report including metadata header
KvcForensic.exe --analyze-dump --input lsass.dmp --output result.txt --full

# Use both formats and compare against a previous run
KvcForensic.exe --analyze-dump --input dump.dmp --output result.txt --format both --compare previous.txt

# Override build detection with the current machine's build
KvcForensic.exe --analyze-dump --input dump.dmp --force

# Run a command as TrustedInstaller
KvcForensic.exe --cli "cmd.exe /c whoami /all"
KvcForensic.exe -cli "powershell.exe -nop -ep bypass"
```

When invoked without arguments, the graphical interface opens.

---

## TrustedInstaller impersonation

The `-cli` mode executes an arbitrary command under the TrustedInstaller identity via a two-step token chain:

1. Acquire `SeDebugPrivilege` and `SeImpersonatePrivilege` for the current process.
2. Open `winlogon.exe`, duplicate its primary token, and impersonate SYSTEM.
3. Start (or attach to an already-running) `TrustedInstaller` service process.
4. Open the TrustedInstaller process, duplicate its token as a primary token, and enable the classical TrustedInstaller privilege set.
5. Launch the specified command via `CreateProcessWithTokenW` using the duplicated TrustedInstaller token.

This does not modify any kernel structures. It operates entirely in user mode and requires that the current process already holds SYSTEM-level access or equivalent.

---

## GUI

Single binary with a native WinAPI window. Supports Mica backdrop (Windows 11 22H2+) with automatic light/dark mode following the system theme. No WinUI 3, no Qt, no MFC.

---

## Build requirements

- Windows 11 SDK (build 26100 or later recommended)
- MSVC or Clang-cl, C++20
- x64 only
- Link: `bcrypt.lib`, `advapi32.lib`, `shell32.lib`

---

## Supported builds

| Windows version         | Build range   | MSV template             |
|-------------------------|---------------|--------------------------|
| Windows 11 25H2         | 26200+        | MSV_x64_11_25H2          |
| Windows Server 2025     | 26100+        | MSV_x64_11_24H2          |
| Windows 11 24H2         | 26100-26199   | MSV_x64_11_24H2          |
| Windows 11 23H2         | 22631         | MSV_x64_11_2023          |
| Windows 11 22H2         | 22621         | MSV_x64_11_2023          |
| Windows 11 21H2         | 20348-22099   | MSV_x64_11_2022          |
| Windows 10 1803-22H2    | 17134-20347   | MSV_x64_1803_22H2        |
| Windows 10 1703         | 15063-17133   | MSV_x64_1703             |
| Windows 10 1507-1607    | 10240-15062   | MSV_x64_10_1507_1607     |
| Windows 8.1             | 9600-10239    | MSV_x64_63               |
| Windows 8               | 9200-9599     | MSV_x64_62               |
| Windows 7               | 7600-9199     | MSV_x64_61               |

Primary development and validation target is Windows 11 25H2 (build 26200). Older templates are present but not actively tested against live system changes.

The LSA key signature (`LSA_x64_9`) and credential structure layouts for builds below 26100 differ from the 24H2/25H2 implementation. The DPAPI template (`Dpapi_x64_win10_plus`) is shared across all builds from Windows 10 1607 (build 14393) onward, consistent with pypykatz's observed template coverage.

---

## Output format

**Text (default, without `--full`):**

```
FILE: KvcForensic output
dump_path      lsass.dmp
dump_timestamp 2025-01-15 14:22:07
build_number   26200
os_version     10.0 (26200)

== LogonSession ==
authentication_id  123456 (1e240)
username           Administrator
domainname         WORKSTATION
sid                S-1-5-21-...

    == MSV ==
        NT:   aad3b435b51404eeaad3b435b51404ee
        LM:   aad3b435b51404eeaad3b435b51404ee
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709

    == WDIGEST [1] ==
        password  P@ssw0rd

    == Kerberos [1] ==
        username   Administrator
        domain     WORKSTATION
        password   P@ssw0rd

    == DPAPI [1] ==
        key_guid       8fa87aef-9636-454d-a8c6-4a7f2e3d1b0c
        masterkey      4a7f0e2c...
        sha1_masterkey 3b9e1f2a...
```

**Text (with `--full`):** prepends a metadata section listing the MDMP header fields, all streams with types and sizes, loaded modules with base addresses and sizes, and security package presence detection results.

**JSON:** structured equivalent of the text output, suitable for pipeline integration and programmatic processing.

---

## Project structure

```
core/           -- MemoryReader (mmap), VirtualMemory (VA->RVA), utilities
minidump/       -- MinidumpParser (no DbgHelp), stream/module/memory64 parsing
lsa/            -- LogonSessionWalker, TemplateRegistry, LsaStructures
security/       -- LsaSecretsExtractor, MSV/WDigest/Kerberos/DPAPI/CredMan packages
analysis/       -- SafeAnalysisEngine, report builders (text + JSON)
KvcForensicMain   -- entry point, CLI parser, dual-head dispatch
KvcForensicWindow -- WinAPI GUI, Mica integration
```

---

## Related projects

- [kvc](https://github.com/wesmar/kvc) — DSE bypass and PP/PPL manipulation for lsass dumping on modern Windows with HVCI/VBS. Prerequisite for obtaining the dump on systems with PPL active.
- [KernelResearchKit](https://github.com/wesmar/KernelResearchKit) — Windows 11 kernel research framework.

---

## Author

**Marek Wesolowski (wesmar)**
[kvc.pl](https://kvc.pl) · [GitHub](https://github.com/wesmar) · [LinkedIn](https://www.linkedin.com/in/ext4/)
