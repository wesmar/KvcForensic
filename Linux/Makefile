CXX ?= g++
CXXFLAGS ?= -std=c++23 -O2 -Wall -Wextra -Wpedantic -Wconversion -Isrc
LDLIBS ?= -lcrypto

BIN := kvcforensic-linux
SRCS := \
    src/main.cpp \
    src/core/crypto_backend.cpp \
    src/core/memory_reader.cpp \
    src/core/module_index.cpp \
    src/core/signature_scanner.cpp \
    src/core/text_utils.cpp \
    src/core/virtual_memory.cpp \
    src/minidump/minidump_parser.cpp \
    src/lsa/template_registry.cpp \
    src/lsa/reader_utils.cpp \
    src/lsa/msv_walker.cpp \
    src/lsa/wdigest_walker.cpp \
    src/lsa/kerberos_walker.cpp \
    src/lsa/dpapi_walker.cpp \
    src/lsa/tspkg_walker.cpp \
    src/lsa/logon_session_walker.cpp \
    src/security/lsa_secrets_extractor.cpp \
    src/analysis/report_builder.cpp \
    src/cli/credential_pipeline.cpp

OBJS := $(SRCS:.cpp=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(BIN) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJS)
