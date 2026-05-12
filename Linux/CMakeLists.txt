cmake_minimum_required(VERSION 3.22)

project(kvcforensic-linux-cli LANGUAGES CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(KVC_SOURCES
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

add_executable(kvcforensic-linux ${KVC_SOURCES})

target_include_directories(kvcforensic-linux PRIVATE src)
target_compile_features(kvcforensic-linux PRIVATE cxx_std_23)
target_link_libraries(kvcforensic-linux PRIVATE OpenSSL::Crypto)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(kvcforensic-linux PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
    )
endif()

install(TARGETS kvcforensic-linux RUNTIME DESTINATION bin)
install(FILES resources/KvcForensic.json DESTINATION share/kvc)
