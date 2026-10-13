// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Dynamic API hash algorithms and resolution engine.
//!
//! Reconstructs resolved API targets from precomputed hashes commonly encountered in
//! shellcode and evasion techniques (ROR13, CRC32, DJB2, FNV-1a).

use serde::Serialize;

use crate::error::{Result, SentinelError};

/// A successfully resolved API symbol match.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApiHashMatch {
    pub algorithm: String,
    pub api_name: String,
    pub dll: String,
    pub hash_hex: String,
    pub hash_value: u32,
}

/// Computes the 32-bit Rotate Right 13 (ROR13) hash of an ASCII string.
pub fn hash_ror13(s: &str) -> u32 {
    let mut h = 0u32;
    for b in s.bytes() {
        h = h.rotate_right(13).wrapping_add(b as u32);
    }
    h
}

/// Computes the standard IEEE 802.3 32-bit CRC32 checksum of an ASCII string.
pub fn hash_crc32(s: &str) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in s.bytes() {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Computes the 32-bit DJB2 hash of an ASCII string (`h = h * 33 + c`).
pub fn hash_djb2(s: &str) -> u32 {
    let mut h = 5381u32;
    for b in s.bytes() {
        h = ((h << 5).wrapping_add(h)).wrapping_add(b as u32);
    }
    h
}

/// Computes the 32-bit Fowler–Noll–Vo 1a (FNV-1a) hash of an ASCII string.
pub fn hash_fnv1a(s: &str) -> u32 {
    let mut h = 0x811C_9DC5u32;
    for b in s.bytes() {
        h = (h ^ (b as u32)).wrapping_mul(0x0100_0193);
    }
    h
}

/// Curated database of high-frequency Windows APIs and their host DLLs.
pub const COMMON_WINDOWS_APIS: &[(&str, &str)] = &[
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "LoadLibraryW"),
    ("kernel32.dll", "LoadLibraryExA"),
    ("kernel32.dll", "LoadLibraryExW"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "VirtualProtectEx"),
    ("kernel32.dll", "VirtualFree"),
    ("kernel32.dll", "CreateProcessA"),
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "ReadProcessMemory"),
    ("kernel32.dll", "OpenProcess"),
    ("kernel32.dll", "CreateFileA"),
    ("kernel32.dll", "CreateFileW"),
    ("kernel32.dll", "ReadFile"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "CloseHandle"),
    ("kernel32.dll", "ExitProcess"),
    ("kernel32.dll", "TerminateProcess"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetModuleHandleW"),
    ("kernel32.dll", "GetModuleFileNameA"),
    ("kernel32.dll", "GetModuleFileNameW"),
    ("kernel32.dll", "Sleep"),
    ("kernel32.dll", "WaitForSingleObject"),
    ("kernel32.dll", "CreateThread"),
    ("kernel32.dll", "QueueUserAPC"),
    ("kernel32.dll", "ResumeThread"),
    ("kernel32.dll", "SetThreadContext"),
    ("kernel32.dll", "GetThreadContext"),
    ("kernel32.dll", "IsDebuggerPresent"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    ("kernel32.dll", "CreateToolhelp32Snapshot"),
    ("kernel32.dll", "Process32First"),
    ("kernel32.dll", "Process32Next"),
    ("kernel32.dll", "Process32FirstW"),
    ("kernel32.dll", "Process32NextW"),
    ("kernel32.dll", "WinExec"),
    ("kernel32.dll", "GetLastError"),
    ("kernel32.dll", "SetLastError"),
    ("kernel32.dll", "MapViewOfFile"),
    ("kernel32.dll", "CreateFileMappingA"),
    ("kernel32.dll", "CreateFileMappingW"),
    ("kernel32.dll", "UnmapViewOfFile"),
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtProtectVirtualMemory"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtReadVirtualMemory"),
    ("ntdll.dll", "NtCreateThreadEx"),
    ("ntdll.dll", "NtOpenProcess"),
    ("ntdll.dll", "NtResumeThread"),
    ("ntdll.dll", "NtQueryInformationProcess"),
    ("ntdll.dll", "NtQuerySystemInformation"),
    ("ntdll.dll", "NtUnmapViewOfSection"),
    ("ntdll.dll", "NtMapViewOfSection"),
    ("ntdll.dll", "RtlCreateUserThread"),
    ("ntdll.dll", "RtlMoveMemory"),
    ("ntdll.dll", "RtlZeroMemory"),
    ("ntdll.dll", "RtlAllocateHeap"),
    ("ntdll.dll", "RtlFreeHeap"),
    ("ntdll.dll", "LdrLoadDll"),
    ("ntdll.dll", "LdrGetProcedureAddress"),
    ("ntdll.dll", "ZwQueryInformationProcess"),
    ("user32.dll", "MessageBoxA"),
    ("user32.dll", "MessageBoxW"),
    ("user32.dll", "GetForegroundWindow"),
    ("user32.dll", "GetAsyncKeyState"),
    ("user32.dll", "GetKeyState"),
    ("user32.dll", "SetWindowsHookExA"),
    ("user32.dll", "SetWindowsHookExW"),
    ("user32.dll", "UnhookWindowsHookEx"),
    ("user32.dll", "CallNextHookEx"),
    ("user32.dll", "GetMessageA"),
    ("user32.dll", "GetMessageW"),
    ("user32.dll", "DispatchMessageA"),
    ("user32.dll", "DispatchMessageW"),
    ("user32.dll", "TranslateMessage"),
    ("user32.dll", "PostQuitMessage"),
    ("advapi32.dll", "RegOpenKeyExA"),
    ("advapi32.dll", "RegOpenKeyExW"),
    ("advapi32.dll", "RegSetValueExA"),
    ("advapi32.dll", "RegSetValueExW"),
    ("advapi32.dll", "RegQueryValueExA"),
    ("advapi32.dll", "RegQueryValueExW"),
    ("advapi32.dll", "RegCloseKey"),
    ("advapi32.dll", "RegCreateKeyExA"),
    ("advapi32.dll", "RegCreateKeyExW"),
    ("advapi32.dll", "OpenProcessToken"),
    ("advapi32.dll", "AdjustTokenPrivileges"),
    ("advapi32.dll", "LookupPrivilegeValueA"),
    ("advapi32.dll", "LookupPrivilegeValueW"),
    ("advapi32.dll", "CryptAcquireContextA"),
    ("advapi32.dll", "CryptAcquireContextW"),
    ("advapi32.dll", "CryptGenRandom"),
    ("advapi32.dll", "CryptReleaseContext"),
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "WSACleanup"),
    ("ws2_32.dll", "socket"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "bind"),
    ("ws2_32.dll", "listen"),
    ("ws2_32.dll", "accept"),
    ("ws2_32.dll", "closesocket"),
    ("ws2_32.dll", "htons"),
    ("ws2_32.dll", "htonl"),
    ("ws2_32.dll", "ntohs"),
    ("ws2_32.dll", "ntohl"),
    ("ws2_32.dll", "inet_addr"),
    ("ws2_32.dll", "inet_ntoa"),
    ("ws2_32.dll", "gethostbyname"),
    ("ws2_32.dll", "WSAGetLastError"),
    ("wininet.dll", "InternetOpenA"),
    ("wininet.dll", "InternetOpenW"),
    ("wininet.dll", "InternetConnectA"),
    ("wininet.dll", "InternetConnectW"),
    ("wininet.dll", "HttpOpenRequestA"),
    ("wininet.dll", "HttpOpenRequestW"),
    ("wininet.dll", "HttpSendRequestA"),
    ("wininet.dll", "HttpSendRequestW"),
    ("wininet.dll", "InternetReadFile"),
    ("wininet.dll", "InternetCloseHandle"),
];

/// Parses a hash string from hexadecimal (e.g. `0xEDB88320` or `EDB88320`) or decimal format.
pub fn parse_hash_string(s: &str) -> Result<u32> {
    let trimmed = s.trim();
    let hex_clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if let Ok(v) = u32::from_str_radix(hex_clean, 16) {
        return Ok(v);
    }
    if let Ok(v) = trimmed.parse::<u32>() {
        return Ok(v);
    }

    Err(SentinelError::InvalidArgument(format!(
        "Invalid 32-bit hash value: '{s}'"
    )))
}

/// Resolves a 32-bit hash target against common Windows DLL exports and caller-provided exports.
pub fn resolve_api_hash(target_hash: u32, extra_exports: &[(&str, &str)]) -> Vec<ApiHashMatch> {
    let mut matches = Vec::new();

    let all_apis = COMMON_WINDOWS_APIS
        .iter()
        .copied()
        .chain(extra_exports.iter().copied());

    for (dll, api) in all_apis {
        // 1. ROR13
        if hash_ror13(api) == target_hash {
            matches.push(ApiHashMatch {
                algorithm: "ROR13".to_string(),
                api_name: api.to_string(),
                dll: dll.to_string(),
                hash_hex: format!("0x{target_hash:08X}"),
                hash_value: target_hash,
            });
        }

        // 2. CRC32
        if hash_crc32(api) == target_hash {
            matches.push(ApiHashMatch {
                algorithm: "CRC32".to_string(),
                api_name: api.to_string(),
                dll: dll.to_string(),
                hash_hex: format!("0x{target_hash:08X}"),
                hash_value: target_hash,
            });
        }

        // 3. DJB2
        if hash_djb2(api) == target_hash {
            matches.push(ApiHashMatch {
                algorithm: "DJB2".to_string(),
                api_name: api.to_string(),
                dll: dll.to_string(),
                hash_hex: format!("0x{target_hash:08X}"),
                hash_value: target_hash,
            });
        }

        // 4. FNV-1a
        if hash_fnv1a(api) == target_hash {
            matches.push(ApiHashMatch {
                algorithm: "FNV-1a".to_string(),
                api_name: api.to_string(),
                dll: dll.to_string(),
                hash_hex: format!("0x{target_hash:08X}"),
                hash_value: target_hash,
            });
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithms() {
        assert_eq!(hash_crc32("123456789"), 0xCBF43926);
        assert_eq!(hash_djb2(""), 5381);
        assert_eq!(hash_fnv1a(""), 0x811C9DC5);

        let va_ror13 = hash_ror13("VirtualAlloc");
        let matches = resolve_api_hash(va_ror13, &[]);
        assert!(matches
            .iter()
            .any(|m| m.algorithm == "ROR13" && m.api_name == "VirtualAlloc"));
    }
}
