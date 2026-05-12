# KvcForensic Linux CLI

Linux port of the KvcForensic engine: minidump parser, VA→RVA resolver, module
slicing, signature scanner, JSON template registry and full credential
extraction pipeline (MSV, WDigest, Kerberos, DPAPI, TSPKG).

Decryption is backed by OpenSSL (`libcrypto`). All credential output matches
the Windows build 1:1 — same NT/SHA1 hashes, same DPAPI master-key GUIDs.

## Dependencies

- C++23 toolchain (gcc 13+ / clang 16+)
- OpenSSL libcrypto headers (Debian/Ubuntu: `libssl-dev`, Fedora: `openssl-devel`)
- POSIX (uses `mmap` for zero-copy dump access)

## Build

CMake:

```bash
cmake -S linux-cli -B linux-cli/build
cmake --build linux-cli/build -j
```

Plain Make:

```bash
make -C linux-cli -j
```

Binary lands at `linux-cli/kvcforensic-linux` (make) or
`linux-cli/build/kvcforensic-linux` (cmake).

## Usage

Windows-compatible analyze mode (writes TXT + JSON next to each other):

```bash
linux-cli/kvcforensic-linux --analyze-dump \
    --input tmp/lsass.dmp \
    --output result.txt \
    --templates linux-cli/resources/KvcForensic.json \
    --format both --full
```

Inspection sub-commands accept the dump path and an optional
`--templates <path>`:

```bash
linux-cli/kvcforensic-linux info        tmp/lsass.dmp
linux-cli/kvcforensic-linux streams     tmp/lsass.dmp
linux-cli/kvcforensic-linux modules     tmp/lsass.dmp
linux-cli/kvcforensic-linux memory-map  tmp/lsass.dmp
linux-cli/kvcforensic-linux slices      tmp/lsass.dmp
linux-cli/kvcforensic-linux templates   --templates resources/KvcForensic.json tmp/lsass.dmp
linux-cli/kvcforensic-linux credentials --templates resources/KvcForensic.json tmp/lsass.dmp
```

Template file resolution order:

1. `--templates <path>` argument
2. `$KVC_TEMPLATES` environment variable
3. Alongside the binary or under `<binary>/resources/`
4. CWD: `KvcForensic.json`, `resources/KvcForensic.json`, `linux-cli/resources/KvcForensic.json`
5. `/etc/kvc/KvcForensic.json`, `/usr/share/kvc/KvcForensic.json`

## Module layout

```
src/
├── core/
│   ├── memory_reader.{h,cpp}    mmap-backed dump view
│   ├── virtual_memory.{h,cpp}   VA→RVA resolver (sorted index, binary search)
│   ├── module_index.{h,cpp}     module × Memory64ListStream intersections
│   ├── signature_scanner.{h,cpp} scan only inside module slices
│   ├── crypto_backend.{h,cpp}   OpenSSL: AES-CFB128, 3DES-CBC, SHA1
│   ├── text_utils.{h,cpp}       UTF-16LE → UTF-8, hex helpers
├── minidump/
│   ├── dbghelp_types.h          Minimal MINIDUMP header / directory structs
│   ├── minidump_parser.{h,cpp}  Header / SystemInfo / ModuleList / Memory64List
├── lsa/
│   ├── structures.h             LUID64, UNICODE_STRING64, credential POD types
│   ├── template_registry.{h,cpp} KvcForensic.json loader (no third-party deps)
│   ├── reader_utils.{h,cpp}     password decode + readability heuristics
│   ├── msv_walker.{h,cpp}       MSV1_0 credential list + CredMan
│   ├── wdigest_walker.{h,cpp}   wdigest.dll list
│   ├── kerberos_walker.{h,cpp}  kerberos.dll AVL tree + ticket lists
│   ├── dpapi_walker.{h,cpp}     KIWI_MASTERKEY_CACHE_ENTRY walker
│   ├── tspkg_walker.{h,cpp}     tspkg.dll list
│   ├── logon_session_walker.{h,cpp} orchestrates all walkers
├── security/
│   └── lsa_secrets_extractor.{h,cpp} locates AES + 3DES + IV in lsasrv.dll
├── analysis/
│   └── report_builder.{h,cpp}   TXT + JSON output
├── cli/
│   └── credential_pipeline.{h,cpp} top-level pipeline + template resolution
└── main.cpp                      CLI dispatch
```

## Tests

A bundled script batches every `tmp/*.dmp` and prints a summary table:

```bash
linux-cli/tests/run_dumps.sh
```

Tested against Windows builds 19045 (Win10 22H2), 26100 (24H2), 26200 (25H2),
28000 (26H1). NT hashes and DPAPI master-key GUIDs match the Windows
reference outputs byte-for-byte on the same dumps.
