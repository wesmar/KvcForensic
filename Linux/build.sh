#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

sources=(
  src/main.cpp
  src/core/crypto_backend.cpp
  src/core/memory_reader.cpp
  src/core/module_index.cpp
  src/core/signature_scanner.cpp
  src/core/text_utils.cpp
  src/core/virtual_memory.cpp
  src/minidump/minidump_parser.cpp
  src/lsa/template_registry.cpp
  src/lsa/reader_utils.cpp
  src/lsa/msv_walker.cpp
  src/lsa/wdigest_walker.cpp
  src/lsa/kerberos_walker.cpp
  src/lsa/dpapi_walker.cpp
  src/lsa/tspkg_walker.cpp
  src/lsa/logon_session_walker.cpp
  src/security/lsa_secrets_extractor.cpp
  src/analysis/report_builder.cpp
  src/cli/credential_pipeline.cpp
)

clean_artifacts() {
  find src -name '*.o' -type f -delete
  rm -rf build
  rm -f kvcforensic-linux
}

case "${1:-build}" in
  build)
    mkdir -p bin
    clean_artifacts

    echo "  [1/2] dynamic..."
    g++ -std=c++23 -O2 -Wall -Wextra -Wpedantic -Wconversion -Isrc \
      "${sources[@]}" -o bin/KvcForensic -lcrypto

    echo "  [2/2] static..."
    g++ -std=c++23 -O2 -Wall -Wextra -Wpedantic -Wconversion -Isrc \
      "${sources[@]}" -o bin/KvcForensic_static \
      -static -lcrypto -lz -lzstd -ljitterentropy -lpthread -ldl

    clean_artifacts
    ls -lh bin/KvcForensic bin/KvcForensic_static
    ;;
  clean)
    clean_artifacts
    rm -f bin/KvcForensic bin/KvcForensic_static
    ;;
  *)
    echo "usage: ./build.sh [build|clean]" >&2
    exit 2
    ;;
esac
