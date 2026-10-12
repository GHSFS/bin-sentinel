// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::Serialize;

/// Encoding of an extracted static string.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

/// Optional Indicator of Compromise (IoC) or notable API classification.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum IocKind {
    Url,
    Ipv4,
    RegistryKey,
    SensitiveApi,
}

/// Single extracted string entry with offset and optional IoC classification.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    pub offset: usize,
    pub encoding: StringEncoding,
    pub value: String,
    pub ioc: Option<IocKind>,
}

const SENSITIVE_APIS: &[&str] = &[
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserApc",
    "SetWindowsHookEx",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "CryptEncrypt",
    "BCryptEncrypt",
];

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

fn looks_like_ipv4(s: &str) -> bool {
    for token in s.split(|c: char| !c.is_ascii_digit() && c != '.') {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
        {
            return true;
        }
    }
    false
}

/// Classifies a string into an Indicator of Compromise (IoC) category if matched.
pub fn classify_ioc(s: &str) -> Option<IocKind> {
    let trimmed = s.trim();
    if trimmed.contains("http://") || trimmed.contains("https://") || trimmed.contains("ftp://") {
        return Some(IocKind::Url);
    }

    let upper = trimmed.to_ascii_uppercase();
    if upper.contains("HKLM\\")
        || upper.contains("HKCU\\")
        || upper.contains("HKEY_LOCAL_MACHINE")
        || upper.contains("HKEY_CURRENT_USER")
        || upper.contains("SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN")
    {
        return Some(IocKind::RegistryKey);
    }

    if SENSITIVE_APIS.iter().any(|api| trimmed.contains(api)) {
        return Some(IocKind::SensitiveApi);
    }

    if looks_like_ipv4(trimmed) {
        return Some(IocKind::Ipv4);
    }

    None
}

/// Extracts printable ASCII and UTF-16LE strings of at least `min_len` characters from `data`.
pub fn extract_strings(data: &[u8], min_len: usize, ioc_only: bool) -> Vec<ExtractedString> {
    let effective_min = min_len.max(2);
    let mut results = Vec::new();

    // 1. Scan contiguous printable ASCII sequences
    let mut start = None;
    for (idx, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s_off) = start.take() {
            if idx - s_off >= effective_min {
                let val = String::from_utf8_lossy(&data[s_off..idx]).to_string();
                let ioc = classify_ioc(&val);
                if !ioc_only || ioc.is_some() {
                    results.push(ExtractedString {
                        offset: s_off,
                        encoding: StringEncoding::Ascii,
                        value: val,
                        ioc,
                    });
                }
            }
        }
    }
    if let Some(s_off) = start {
        if data.len() - s_off >= effective_min {
            let val = String::from_utf8_lossy(&data[s_off..]).to_string();
            let ioc = classify_ioc(&val);
            if !ioc_only || ioc.is_some() {
                results.push(ExtractedString {
                    offset: s_off,
                    encoding: StringEncoding::Ascii,
                    value: val,
                    ioc,
                });
            }
        }
    }

    // 2. Scan contiguous UTF-16LE (ASCII range with 0x00 high byte) sequences
    for parity in 0..2 {
        let mut idx = parity;
        let mut utf16_start: Option<usize> = None;
        let mut chars: Vec<u8> = Vec::new();

        while idx + 1 < data.len() {
            let lo = data[idx];
            let hi = data[idx + 1];
            if is_printable_ascii(lo) && hi == 0 {
                if utf16_start.is_none() {
                    utf16_start = Some(idx);
                }
                chars.push(lo);
            } else if let Some(s_off) = utf16_start.take() {
                if chars.len() >= effective_min {
                    let val = String::from_utf8_lossy(&chars).to_string();
                    let ioc = classify_ioc(&val);
                    if !ioc_only || ioc.is_some() {
                        results.push(ExtractedString {
                            offset: s_off,
                            encoding: StringEncoding::Utf16Le,
                            value: val,
                            ioc,
                        });
                    }
                }
                chars.clear();
            }
            idx += 2;
        }

        if let Some(s_off) = utf16_start {
            if chars.len() >= effective_min {
                let val = String::from_utf8_lossy(&chars).to_string();
                let ioc = classify_ioc(&val);
                if !ioc_only || ioc.is_some() {
                    results.push(ExtractedString {
                        offset: s_off,
                        encoding: StringEncoding::Utf16Le,
                        value: val,
                        ioc,
                    });
                }
            }
        }
    }

    results.sort_by_key(|e| e.offset);
    results
}
