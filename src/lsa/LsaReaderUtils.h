#pragma once

#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace KvcForensic::lsa {

// ---------------------------------------------------------------------------
// Shared low-level helpers used by LogonSessionWalker and all package walkers.
// ---------------------------------------------------------------------------

std::wstring ReadUnicodeString(const core::VirtualMemory& vmem, std::uint64_t string_va);
std::string  ReadSid(const core::VirtualMemory& vmem, std::uint64_t sid_va);

std::uint64_t FindSignatureInModule(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    const std::wstring& module_name,
    const std::vector<std::uint8_t>& sig);

std::wstring Utf16ToWString(const std::vector<std::byte>& data);
std::wstring BytesToHexString(std::span<const std::byte> bytes);
bool IsLikelyReadablePassword(const std::wstring& text);

void DecodePasswordCandidate(
    const std::vector<std::byte>& decrypted,
    std::uint16_t utf16_byte_len_hint,
    std::wstring& out_password,
    std::wstring& out_password_hex);

std::string ComputeSha1(std::span<const std::byte> data);

} // namespace KvcForensic::lsa
