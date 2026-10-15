// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{CarveEncodingKind, CarvedPayload, DecodedPayloadKind};
use crate::entropy::shannon_entropy;
use crate::patch::sha256_hex;

/// Classifies a decoded byte payload and constructs a rich `CarvedPayload`.
pub fn classify_payload(
    id: usize,
    encoding: CarveEncodingKind,
    file_offset: usize,
    encoded_length: usize,
    decoded: Vec<u8>,
) -> CarvedPayload {
    let decoded_length = decoded.len();
    let entropy = shannon_entropy(&decoded);
    let sha256 = sha256_hex(&decoded);

    let (payload_kind, confidence_score, summary) = inspect_decoded_content(&decoded, entropy);
    let preview_hex = format_hex_preview(&decoded, 16);
    let preview_text = format_text_preview(&decoded, 32);

    CarvedPayload {
        id,
        encoding,
        file_offset,
        encoded_length,
        decoded_length,
        section_name: None,
        rva: None,
        is_rwx_section: false,
        entropy,
        sha256,
        payload_kind,
        confidence_score,
        summary,
        preview_hex,
        preview_text,
        decoded_bytes: decoded,
    }
}

fn inspect_decoded_content(bytes: &[u8], entropy: f64) -> (DecodedPayloadKind, u8, String) {
    // 1. Nested PE Executable / DLL
    if bytes.len() >= 0x40 && bytes[0] == b'M' && bytes[1] == b'Z' {
        let e_lfanew =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if e_lfanew + 24 <= bytes.len() && &bytes[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            let machine = u16::from_le_bytes([bytes[e_lfanew + 4], bytes[e_lfanew + 5]]);
            let chars = u16::from_le_bytes([bytes[e_lfanew + 22], bytes[e_lfanew + 23]]);
            let is_64bit = machine == 0x8664 || machine == 0xAA64;
            let is_dll = (chars & 0x2000) != 0;
            let kind_str = if is_dll { "DLL" } else { "EXE" };
            let arch_str = if is_64bit { "x64" } else { "x86" };
            return (
                DecodedPayloadKind::NestedPe { is_64bit, is_dll },
                98,
                format!("Nested PE {arch_str} {kind_str} (PE sig @ offset 0x{e_lfanew:X})"),
            );
        }
    }

    // 2. Nested Linux ELF Executable / SO
    if bytes.len() >= 16 && &bytes[0..4] == b"\x7FELF" {
        let is_64bit = bytes[4] == 2;
        let arch_str = if is_64bit { "64-bit" } else { "32-bit" };
        return (
            DecodedPayloadKind::NestedElf { is_64bit },
            98,
            format!("Nested Linux ELF {arch_str} binary"),
        );
    }

    // 3. Nested Apple Mach-O Binary
    if bytes.len() >= 4 {
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic == 0xFEEDFACF || magic == 0xCFFAEDFE {
            return (
                DecodedPayloadKind::NestedMacho {
                    is_64bit: true,
                    is_fat: false,
                },
                96,
                "Nested Apple Mach-O 64-bit binary".to_string(),
            );
        } else if magic == 0xFEEDFACE || magic == 0xCEFAEDFE {
            return (
                DecodedPayloadKind::NestedMacho {
                    is_64bit: false,
                    is_fat: false,
                },
                95,
                "Nested Apple Mach-O 32-bit binary".to_string(),
            );
        } else if magic == 0xCAFEBABE || magic == 0xBEBAFECA {
            return (
                DecodedPayloadKind::NestedMacho {
                    is_64bit: true,
                    is_fat: true,
                },
                95,
                "Nested Apple Mach-O Universal Fat binary".to_string(),
            );
        }
    }

    // 4. Archive Containers
    if bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04" {
        return (
            DecodedPayloadKind::ArchiveZip,
            92,
            "ZIP / Office / JAR container archive".to_string(),
        );
    }
    if bytes.len() >= 2 && &bytes[0..2] == b"\x1F\x8B" {
        return (
            DecodedPayloadKind::ArchiveGzip,
            90,
            "GZIP compressed stream".to_string(),
        );
    }
    if bytes.len() >= 6 && &bytes[0..6] == b"7z\xBC\xAF\x27\x1C" {
        return (
            DecodedPayloadKind::Archive7z,
            95,
            "7-Zip archive container".to_string(),
        );
    }
    if bytes.len() >= 5 && &bytes[0..5] == b"%PDF-" {
        return (
            DecodedPayloadKind::DocumentPdf,
            92,
            "Adobe PDF document container".to_string(),
        );
    }

    // 5. Script & Shell Heuristics (Convert ASCII/UTF-8 and UTF-16LE text)
    let text_content = extract_lossy_text(bytes);
    let lower_text = text_content.to_ascii_lowercase();

    let ps_keywords = [
        "powershell",
        "invoke-expression",
        "iex",
        "downloadstring",
        "downloadfile",
        "system.net.webclient",
        "start-process",
        "bypass",
        "frombase64string",
        "-encodedcommand",
        "-enc",
        "memorystream",
    ];
    let mut ps_triggers = Vec::new();
    for kw in ps_keywords {
        if lower_text.contains(kw) {
            ps_triggers.push(kw.to_string());
        }
    }
    if ps_triggers.len() >= 2 || (ps_triggers.len() == 1 && lower_text.contains("powershell")) {
        return (
            DecodedPayloadKind::ScriptPowerShell {
                triggers: ps_triggers.clone(),
            },
            92,
            format!("PowerShell script cradle ({})", ps_triggers.join(", ")),
        );
    }

    let sh_keywords = [
        "#!/bin/",
        "#!/usr/bin/",
        "curl ",
        "wget ",
        "chmod +x",
        "/bin/sh",
        "/bin/bash",
        "bash -i",
        "nc -e",
        "/dev/tcp/",
        "mkfifo",
    ];
    let mut sh_triggers = Vec::new();
    for kw in sh_keywords {
        if lower_text.contains(kw) {
            sh_triggers.push(kw.to_string());
        }
    }
    if !sh_triggers.is_empty() {
        return (
            DecodedPayloadKind::ScriptShell {
                triggers: sh_triggers.clone(),
            },
            88,
            format!("Unix Shell script ({})", sh_triggers.join(", ")),
        );
    }

    let batch_keywords = [
        "@echo off",
        "cmd.exe",
        "certutil -decode",
        "bitsadmin /transfer",
    ];
    let mut batch_triggers = Vec::new();
    for kw in batch_keywords {
        if lower_text.contains(kw) {
            batch_triggers.push(kw.to_string());
        }
    }
    if !batch_triggers.is_empty() {
        return (
            DecodedPayloadKind::ScriptBatch {
                triggers: batch_triggers.clone(),
            },
            85,
            format!("Batch script command ({})", batch_triggers.join(", ")),
        );
    }

    // 6. Network IoCs (URLs & IPv4)
    let urls = extract_urls(&text_content);
    let ips = extract_ipv4(&text_content);
    if !urls.is_empty() || !ips.is_empty() {
        return (
            DecodedPayloadKind::IocNetwork {
                urls: urls.clone(),
                ips: ips.clone(),
            },
            85,
            format!(
                "Network IoC payload ({} URLs, {} IPs)",
                urls.len(),
                ips.len()
            ),
        );
    }

    // 7. High-Entropy Shellcode Heuristics
    if entropy >= 6.8 {
        let has_prologue = contains_prologue_or_syscall(bytes);
        return (
            DecodedPayloadKind::HighEntropyShellcode {
                entropy,
                possible_prologue: has_prologue,
            },
            if has_prologue { 85 } else { 75 },
            format!(
                "High-entropy binary payload (entropy: {entropy:.2}{})",
                if has_prologue {
                    ", shellcode stub detected"
                } else {
                    ""
                }
            ),
        );
    }

    // 8. Plain Text / Configuration
    if std::str::from_utf8(bytes).is_ok() && text_content.len() >= 16 {
        return (
            DecodedPayloadKind::TextOrData { is_utf8: true },
            65,
            "Valid UTF-8 printable text / data".to_string(),
        );
    }

    (
        DecodedPayloadKind::UnknownBinary,
        40,
        format!("Raw binary payload (entropy: {entropy:.2})"),
    )
}

fn contains_prologue_or_syscall(bytes: &[u8]) -> bool {
    // Check x86/x64 function prologues or direct syscalls:
    // 55 48 89 E5 (push rbp; mov rbp, rsp)
    // 48 83 EC (sub rsp, imm8)
    // 4C 8B D1 B8 (mov r10, rcx; mov eax, imm32)
    // 0F 05 (syscall)
    // 90 90 90 90 (NOP sled)
    for window in bytes.windows(4) {
        if window == [0x55, 0x48, 0x89, 0xE5]
            || window == [0x4C, 0x8B, 0xD1, 0xB8]
            || window == [0x90, 0x90, 0x90, 0x90]
        {
            return true;
        }
    }
    for window in bytes.windows(2) {
        if window == [0x0F, 0x05] || window == [0xCD, 0x80] {
            return true;
        }
    }
    false
}

fn extract_lossy_text(bytes: &[u8]) -> String {
    // Try ASCII/UTF-8
    let s = String::from_utf8_lossy(bytes);
    if s.chars().filter(|c| c.is_alphanumeric()).count() >= 8 {
        return s.to_string();
    }
    // Try UTF-16LE
    if bytes.len() >= 4 {
        let u16_chars: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let s16 = String::from_utf16_lossy(&u16_chars);
        if s16.chars().filter(|c| c.is_alphanumeric()).count() >= 8 {
            return s16;
        }
    }
    s.to_string()
}

fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for token in text.split_whitespace() {
        let clean = token.trim_matches(|c| {
            c == '\'' || c == '"' || c == '(' || c == ')' || c == ';' || c == ','
        });
        if (clean.starts_with("http://")
            || clean.starts_with("https://")
            || clean.starts_with("ftp://"))
            && clean.len() >= 10
        {
            urls.push(clean.to_string());
        }
    }
    urls.truncate(10);
    urls
}

fn extract_ipv4(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for token in text.split_whitespace() {
        let clean = token.trim_matches(|c| !char::is_ascii_digit(&c) && c != '.');
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() == 4 {
            let mut valid = true;
            for p in &parts {
                if let Ok(n) = p.parse::<u8>() {
                    if *p != n.to_string() {
                        valid = false;
                        break;
                    }
                } else {
                    valid = false;
                    break;
                }
            }
            if valid && !ips.contains(&clean.to_string()) {
                ips.push(clean.to_string());
            }
        }
    }
    ips.truncate(10);
    ips
}

fn format_hex_preview(bytes: &[u8], max_len: usize) -> String {
    let take = bytes.len().min(max_len);
    let mut hex = String::with_capacity(take * 3);
    for (idx, &b) in bytes[..take].iter().enumerate() {
        if idx > 0 {
            hex.push(' ');
        }
        use std::fmt::Write;
        let _ = write!(hex, "{:02X}", b);
    }
    if bytes.len() > max_len {
        hex.push_str(" ...");
    }
    hex
}

fn format_text_preview(bytes: &[u8], max_len: usize) -> String {
    let take = bytes.len().min(max_len);
    let mut text = String::with_capacity(take);
    for &b in &bytes[..take] {
        if (0x20..=0x7E).contains(&b) {
            text.push(b as char);
        } else {
            text.push('.');
        }
    }
    if bytes.len() > max_len {
        text.push_str("...");
    }
    text
}
