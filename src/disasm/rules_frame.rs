// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Function prologue and epilogue pattern matching rules for x86/x86_64.

use super::patterns::format_bytes_hex;
use super::types::{CodePatternKind, CodePatternMatch};

/// Matches x86 and x86_64 function prologues and epilogues at `offset`.
pub fn match_frame_pattern_at(data: &[u8], offset: usize) -> Option<CodePatternMatch> {
    if offset >= data.len() {
        return None;
    }

    // 1. Compound Function Prologues with Frame Pointer and Stack Allocation
    // 55 48 89 E5 48 83 EC <imm8> (push rbp; mov rbp, rsp; sub rsp, imm8)
    if offset + 8 <= data.len()
        && data[offset..offset + 4] == [0x55, 0x48, 0x89, 0xE5]
        && data[offset + 4..offset + 7] == [0x48, 0x83, 0xEC]
    {
        let imm = data[offset + 7];
        return Some(CodePatternMatch {
            pattern_id: "x64-prologue-frame-sub-imm8".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("push rbp; mov rbp, rsp; sub rsp, 0x{imm:02X}"),
            offset,
            length: 8,
            bytes_hex: format_bytes_hex(&data[offset..offset + 8]),
            section_name: None,
            relative_virtual_address: None,
            description: format!(
                "Standard x64 function prologue with 0x{imm:02X} stack allocation"
            ),
            risk_alert: None,
        });
    }

    // 55 48 89 E5 48 81 EC <imm32> (push rbp; mov rbp, rsp; sub rsp, imm32)
    if offset + 11 <= data.len()
        && data[offset..offset + 4] == [0x55, 0x48, 0x89, 0xE5]
        && data[offset + 4..offset + 7] == [0x48, 0x81, 0xEC]
    {
        let imm_bytes: [u8; 4] = data[offset + 7..offset + 11].try_into().unwrap_or([0; 4]);
        let imm = u32::from_le_bytes(imm_bytes);
        return Some(CodePatternMatch {
            pattern_id: "x64-prologue-frame-sub-imm32".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("push rbp; mov rbp, rsp; sub rsp, 0x{imm:X}"),
            offset,
            length: 11,
            bytes_hex: format_bytes_hex(&data[offset..offset + 11]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("Standard x64 function prologue with 0x{imm:X} stack allocation"),
            risk_alert: None,
        });
    }

    // 55 48 89 E5 (push rbp; mov rbp, rsp)
    if offset + 4 <= data.len() && data[offset..offset + 4] == [0x55, 0x48, 0x89, 0xE5] {
        return Some(CodePatternMatch {
            pattern_id: "x64-prologue-frame".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: "push rbp; mov rbp, rsp".to_string(),
            offset,
            length: 4,
            bytes_hex: format_bytes_hex(&data[offset..offset + 4]),
            section_name: None,
            relative_virtual_address: None,
            description: "Standard x64 frame pointer setup prologue".to_string(),
            risk_alert: None,
        });
    }

    // 55 48 8B EC (push rbp; mov rbp, rsp [alternate encoding])
    if offset + 4 <= data.len() && data[offset..offset + 4] == [0x55, 0x48, 0x8B, 0xEC] {
        return Some(CodePatternMatch {
            pattern_id: "x64-prologue-frame-alt".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: "push rbp; mov rbp, rsp (alt)".to_string(),
            offset,
            length: 4,
            bytes_hex: format_bytes_hex(&data[offset..offset + 4]),
            section_name: None,
            relative_virtual_address: None,
            description: "Standard x64 frame pointer setup (alternate encoding)".to_string(),
            risk_alert: None,
        });
    }

    // 40 55 48 83 EC <imm8> (push rbp; sub rsp, imm8)
    if offset + 6 <= data.len()
        && data[offset..offset + 2] == [0x40, 0x55]
        && data[offset + 2..offset + 5] == [0x48, 0x83, 0xEC]
    {
        let imm = data[offset + 5];
        return Some(CodePatternMatch {
            pattern_id: "win64-prologue-push-rbp-sub".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("push rbp; sub rsp, 0x{imm:02X}"),
            offset,
            length: 6,
            bytes_hex: format_bytes_hex(&data[offset..offset + 6]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("Windows x64 function prologue with 0x{imm:02X} stack frame"),
            risk_alert: None,
        });
    }

    // 40 53 48 83 EC <imm8> (push rbx; sub rsp, imm8)
    if offset + 6 <= data.len()
        && data[offset..offset + 2] == [0x40, 0x53]
        && data[offset + 2..offset + 5] == [0x48, 0x83, 0xEC]
    {
        let imm = data[offset + 5];
        return Some(CodePatternMatch {
            pattern_id: "win64-prologue-push-rbx-sub".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("push rbx; sub rsp, 0x{imm:02X}"),
            offset,
            length: 6,
            bytes_hex: format_bytes_hex(&data[offset..offset + 6]),
            section_name: None,
            relative_virtual_address: None,
            description: format!(
                "Windows x64 function prologue preserving RBX with 0x{imm:02X} stack frame"
            ),
            risk_alert: None,
        });
    }

    // 48 83 EC <imm8> (sub rsp, imm8)
    if offset + 4 <= data.len() && data[offset..offset + 3] == [0x48, 0x83, 0xEC] {
        let imm = data[offset + 3];
        return Some(CodePatternMatch {
            pattern_id: "x64-prologue-sub-rsp-imm8".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("sub rsp, 0x{imm:02X}"),
            offset,
            length: 4,
            bytes_hex: format_bytes_hex(&data[offset..offset + 4]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("x64 stack pointer allocation (0x{imm:02X} bytes)"),
            risk_alert: None,
        });
    }

    // 48 81 EC <imm32> (sub rsp, imm32)
    if offset + 7 <= data.len() && data[offset..offset + 3] == [0x48, 0x81, 0xEC] {
        let imm_bytes: [u8; 4] = data[offset + 3..offset + 7].try_into().unwrap_or([0; 4]);
        let imm = u32::from_le_bytes(imm_bytes);
        return Some(CodePatternMatch {
            pattern_id: "x64-prologue-sub-rsp-imm32".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("sub rsp, 0x{imm:X}"),
            offset,
            length: 7,
            bytes_hex: format_bytes_hex(&data[offset..offset + 7]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("x64 large stack pointer allocation (0x{imm:X} bytes)"),
            risk_alert: None,
        });
    }

    // 48 89 5C 24 <disp8> (mov [rsp+disp8], rbx)
    if offset + 5 <= data.len() && data[offset..offset + 4] == [0x48, 0x89, 0x5C, 0x24] {
        let disp = data[offset + 4];
        return Some(CodePatternMatch {
            pattern_id: "win64-prologue-save-rbx".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: format!("mov [rsp+0x{disp:02X}], rbx"),
            offset,
            length: 5,
            bytes_hex: format_bytes_hex(&data[offset..offset + 5]),
            section_name: None,
            relative_virtual_address: None,
            description: format!(
                "Windows x64 non-volatile register home store for RBX at rsp+0x{disp:02X}"
            ),
            risk_alert: None,
        });
    }

    // 48 89 4C 24 08 (mov [rsp+8], rcx)
    if offset + 5 <= data.len() && data[offset..offset + 5] == [0x48, 0x89, 0x4C, 0x24, 0x08] {
        return Some(CodePatternMatch {
            pattern_id: "win64-prologue-shadow-rcx".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: "mov [rsp+0x08], rcx".to_string(),
            offset,
            length: 5,
            bytes_hex: format_bytes_hex(&data[offset..offset + 5]),
            section_name: None,
            relative_virtual_address: None,
            description: "Windows x64 fastcall shadow space argument spill (RCX)".to_string(),
            risk_alert: None,
        });
    }

    // 55 89 E5 (push ebp; mov ebp, esp - x86 32-bit legacy prologue)
    if offset + 3 <= data.len() && data[offset..offset + 3] == [0x55, 0x89, 0xE5] {
        return Some(CodePatternMatch {
            pattern_id: "x86-prologue-legacy-frame".to_string(),
            category: CodePatternKind::Prologue,
            mnemonic: "push ebp; mov ebp, esp".to_string(),
            offset,
            length: 3,
            bytes_hex: format_bytes_hex(&data[offset..offset + 3]),
            section_name: None,
            relative_virtual_address: None,
            description: "Legacy x86 32-bit frame pointer setup prologue".to_string(),
            risk_alert: None,
        });
    }

    // 2. Function Epilogues
    // 48 89 EC 5D C3 (mov rsp, rbp; pop rbp; ret)
    if offset + 5 <= data.len() && data[offset..offset + 5] == [0x48, 0x89, 0xEC, 0x5D, 0xC3] {
        return Some(CodePatternMatch {
            pattern_id: "x64-epilogue-frame".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: "mov rsp, rbp; pop rbp; ret".to_string(),
            offset,
            length: 5,
            bytes_hex: format_bytes_hex(&data[offset..offset + 5]),
            section_name: None,
            relative_virtual_address: None,
            description: "Standard x64 frame teardown epilogue".to_string(),
            risk_alert: None,
        });
    }

    // 48 83 C4 <imm8> C3 (add rsp, imm8; ret)
    if offset + 5 <= data.len()
        && data[offset..offset + 3] == [0x48, 0x83, 0xC4]
        && data[offset + 4] == 0xC3
    {
        let imm = data[offset + 3];
        return Some(CodePatternMatch {
            pattern_id: "x64-epilogue-add-imm8-ret".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: format!("add rsp, 0x{imm:02X}; ret"),
            offset,
            length: 5,
            bytes_hex: format_bytes_hex(&data[offset..offset + 5]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("x64 stack restoration and return (0x{imm:02X} bytes reclaimed)"),
            risk_alert: None,
        });
    }

    // 48 81 C4 <imm32> C3 (add rsp, imm32; ret)
    if offset + 8 <= data.len()
        && data[offset..offset + 3] == [0x48, 0x81, 0xC4]
        && data[offset + 7] == 0xC3
    {
        let imm_bytes: [u8; 4] = data[offset + 3..offset + 7].try_into().unwrap_or([0; 4]);
        let imm = u32::from_le_bytes(imm_bytes);
        return Some(CodePatternMatch {
            pattern_id: "x64-epilogue-add-imm32-ret".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: format!("add rsp, 0x{imm:X}; ret"),
            offset,
            length: 8,
            bytes_hex: format_bytes_hex(&data[offset..offset + 8]),
            section_name: None,
            relative_virtual_address: None,
            description: format!(
                "x64 large stack restoration and return (0x{imm:X} bytes reclaimed)"
            ),
            risk_alert: None,
        });
    }

    // C9 C3 (leave; ret)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0xC9, 0xC3] {
        return Some(CodePatternMatch {
            pattern_id: "x86-epilogue-leave-ret".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: "leave; ret".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "High-level stack frame teardown and return".to_string(),
            risk_alert: None,
        });
    }

    // 5D C3 (pop rbp; ret)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0x5D, 0xC3] {
        return Some(CodePatternMatch {
            pattern_id: "x64-epilogue-pop-rbp-ret".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: "pop rbp; ret".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Frame pointer restoration and return".to_string(),
            risk_alert: None,
        });
    }

    // C2 <imm16> (ret imm16)
    if offset + 3 <= data.len() && data[offset] == 0xC2 {
        let imm_bytes: [u8; 2] = data[offset + 1..offset + 3].try_into().unwrap_or([0; 2]);
        let imm = u16::from_le_bytes(imm_bytes);
        return Some(CodePatternMatch {
            pattern_id: "x86-epilogue-ret-imm16".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: format!("ret 0x{imm:04X}"),
            offset,
            length: 3,
            bytes_hex: format_bytes_hex(&data[offset..offset + 3]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("Near return popping 0x{imm:04X} caller bytes"),
            risk_alert: None,
        });
    }

    // C3 (ret)
    if data[offset] == 0xC3 {
        return Some(CodePatternMatch {
            pattern_id: "x86-epilogue-ret".to_string(),
            category: CodePatternKind::Epilogue,
            mnemonic: "ret".to_string(),
            offset,
            length: 1,
            bytes_hex: "C3".to_string(),
            section_name: None,
            relative_virtual_address: None,
            description: "Standard near subroutine return".to_string(),
            risk_alert: None,
        });
    }

    None
}
