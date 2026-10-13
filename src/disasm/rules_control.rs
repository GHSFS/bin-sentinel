// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! System call, timing check, VM probe, trap, and indirect branch pattern rules.

use super::patterns::format_bytes_hex;
use super::types::{CodePatternKind, CodePatternMatch};

/// Matches direct system calls, anti-debugging, VM checks, traps, and indirect branches at `offset`.
pub fn match_control_pattern_at(data: &[u8], offset: usize) -> Option<CodePatternMatch> {
    if offset >= data.len() {
        return None;
    }

    // 1. Windows NT Direct Syscall Stub (SysWhispers / Hell's Gate / Halo's Gate pattern)
    // 4C 8B D1 B8 <ssn: 4 bytes> 0F 05 [C3]
    if offset + 10 <= data.len()
        && data[offset..offset + 3] == [0x4C, 0x8B, 0xD1]
        && data[offset + 3] == 0xB8
        && data[offset + 8..offset + 10] == [0x0F, 0x05]
    {
        let has_ret = offset + 11 <= data.len() && data[offset + 10] == 0xC3;
        let len = if has_ret { 11 } else { 10 };
        let ssn_bytes: [u8; 4] = data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]);
        let ssn = u32::from_le_bytes(ssn_bytes);
        let ret_suffix = if has_ret { "; ret" } else { "" };

        return Some(CodePatternMatch {
            pattern_id: "win64-direct-syscall-stub".to_string(),
            category: CodePatternKind::DirectSyscall,
            mnemonic: format!("mov r10, rcx; mov eax, 0x{ssn:X}; syscall{ret_suffix}"),
            offset,
            length: len,
            bytes_hex: format_bytes_hex(&data[offset..offset + len]),
            section_name: None,
            relative_virtual_address: None,
            description: format!(
                "Direct Windows x64 syscall invocation (SSN: 0x{ssn:X}, SysWhispers/Hell's Gate stub)"
            ),
            risk_alert: Some(
                "Direct syscall stub detected (user-mode NTAPI hook / EDR evasion indicator)"
                    .to_string(),
            ),
        });
    }

    // 2. Linux x86_64 Direct Syscall Stub: B8 <sys_nr: 4 bytes> 0F 05 [C3]
    if offset + 7 <= data.len()
        && data[offset] == 0xB8
        && data[offset + 5..offset + 7] == [0x0F, 0x05]
    {
        let has_ret = offset + 8 <= data.len() && data[offset + 7] == 0xC3;
        let len = if has_ret { 8 } else { 7 };
        let sys_bytes: [u8; 4] = data[offset + 1..offset + 5].try_into().unwrap_or([0; 4]);
        let sys_nr = u32::from_le_bytes(sys_bytes);
        let ret_suffix = if has_ret { "; ret" } else { "" };

        return Some(CodePatternMatch {
            pattern_id: "linux64-direct-syscall-stub".to_string(),
            category: CodePatternKind::DirectSyscall,
            mnemonic: format!("mov eax, {sys_nr}; syscall{ret_suffix}"),
            offset,
            length: len,
            bytes_hex: format_bytes_hex(&data[offset..offset + len]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("Direct Linux x86_64 system call (syscall number: {sys_nr})"),
            risk_alert: Some(
                "Direct syscall stub detected (kernel API bypass indicator)".to_string(),
            ),
        });
    }

    // 3. Standalone Kernel Syscalls
    // 0F 05 (syscall)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0x0F, 0x05] {
        return Some(CodePatternMatch {
            pattern_id: "x64-syscall".to_string(),
            category: CodePatternKind::DirectSyscall,
            mnemonic: "syscall".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Direct x86_64 system call instruction".to_string(),
            risk_alert: Some("Standalone x86_64 SYSCALL instruction detected".to_string()),
        });
    }

    // CD 80 (int 0x80)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0xCD, 0x80] {
        return Some(CodePatternMatch {
            pattern_id: "x86-int80-syscall".to_string(),
            category: CodePatternKind::DirectSyscall,
            mnemonic: "int 0x80".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Legacy 32-bit Linux software interrupt syscall (int 0x80)".to_string(),
            risk_alert: Some("Legacy 32-bit Linux INT 0x80 syscall trap detected".to_string()),
        });
    }

    // 4. Anti-Debugging / Timing Measurement Instructions
    // 0F 01 F9 (rdtscp)
    if offset + 3 <= data.len() && data[offset..offset + 3] == [0x0F, 0x01, 0xF9] {
        return Some(CodePatternMatch {
            pattern_id: "x86-rdtscp-timing".to_string(),
            category: CodePatternKind::AntiDebugTiming,
            mnemonic: "rdtscp".to_string(),
            offset,
            length: 3,
            bytes_hex: format_bytes_hex(&data[offset..offset + 3]),
            section_name: None,
            relative_virtual_address: None,
            description: "Read Time-Stamp Counter and Processor ID (serialized timestamp probe)".to_string(),
            risk_alert: Some(
                "RDTSCP serialized timing check (anti-debug latency measurement or sleep-skip evasion)"
                    .to_string(),
            ),
        });
    }

    // 0F 31 (rdtsc)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0x0F, 0x31] {
        return Some(CodePatternMatch {
            pattern_id: "x86-rdtsc-timing".to_string(),
            category: CodePatternKind::AntiDebugTiming,
            mnemonic: "rdtsc".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Read Time-Stamp Counter (high-resolution cycle timer query)".to_string(),
            risk_alert: Some(
                "RDTSC timing check (anti-debug latency measurement or execution delta check)"
                    .to_string(),
            ),
        });
    }

    // 5. Virtual Machine & Hypervisor Fingerprinting Instructions
    // 0F A2 (cpuid)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0x0F, 0xA2] {
        return Some(CodePatternMatch {
            pattern_id: "x86-cpuid-check".to_string(),
            category: CodePatternKind::VmHypervisorCheck,
            mnemonic: "cpuid".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "CPU Identification query (hypervisor leaf detection or feature query)"
                .to_string(),
            risk_alert: Some(
                "CPUID instruction (hypervisor fingerprinting or processor feature probe)"
                    .to_string(),
            ),
        });
    }

    // 0F 01 F0 or 0F 01 E0 (smsw - Store Machine Status Word)
    if offset + 3 <= data.len()
        && (data[offset..offset + 3] == [0x0F, 0x01, 0xF0]
            || data[offset..offset + 3] == [0x0F, 0x01, 0xE0])
    {
        return Some(CodePatternMatch {
            pattern_id: "x86-smsw-check".to_string(),
            category: CodePatternKind::VmHypervisorCheck,
            mnemonic: "smsw".to_string(),
            offset,
            length: 3,
            bytes_hex: format_bytes_hex(&data[offset..offset + 3]),
            section_name: None,
            relative_virtual_address: None,
            description: "Store Machine Status Word query (legacy red pill VM detection check)"
                .to_string(),
            risk_alert: Some(
                "SMSW machine status query (virtual machine detection artifact)".to_string(),
            ),
        });
    }

    // 6. Software Traps and Breakpoints
    // 0F 0B (ud2)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0x0F, 0x0B] {
        return Some(CodePatternMatch {
            pattern_id: "x86-ud2-trap".to_string(),
            category: CodePatternKind::SoftwareTrap,
            mnemonic: "ud2".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Undefined Instruction trap (compiler panic / unreachable assertion trap)"
                .to_string(),
            risk_alert: Some(
                "UD2 trap detected (compiler panic or unreachable assertion trap)".to_string(),
            ),
        });
    }

    // 0xCC (int 3)
    if data[offset] == 0xCC {
        let mut run = 0;
        while offset + run < data.len() && data[offset + run] == 0xCC {
            run += 1;
        }
        let is_padding = run >= 4;
        let id = if is_padding {
            "x86-int3-padding"
        } else {
            "x86-int3-trap"
        };
        let mnemonic = if is_padding {
            format!("int 3 (x{run} function padding)")
        } else {
            format!("int 3 (x{run} break trap)")
        };
        let alert = if is_padding {
            None
        } else {
            Some("Software breakpoint trap (INT 3) detected".to_string())
        };
        let desc = if is_padding {
            format!("Alignment byte padding between subroutines ({run} consecutive bytes)")
        } else {
            format!("Debugger software breakpoint trap ({run} byte trap)")
        };

        return Some(CodePatternMatch {
            pattern_id: id.to_string(),
            category: CodePatternKind::SoftwareTrap,
            mnemonic,
            offset,
            length: run,
            bytes_hex: format_bytes_hex(&data[offset..offset + run.min(16)]),
            section_name: None,
            relative_virtual_address: None,
            description: desc,
            risk_alert: alert,
        });
    }

    // F1 (icebp / int 1)
    if data[offset] == 0xF1 {
        return Some(CodePatternMatch {
            pattern_id: "x86-icebp-trap".to_string(),
            category: CodePatternKind::SoftwareTrap,
            mnemonic: "icebp / int 1".to_string(),
            offset,
            length: 1,
            bytes_hex: "F1".to_string(),
            section_name: None,
            relative_virtual_address: None,
            description: "In-Circuit Emulator single-step debug break trap (ICEBP)".to_string(),
            risk_alert: Some(
                "In-circuit emulator breakpoint trap (ICEBP/INT 1) detected".to_string(),
            ),
        });
    }

    // CE (into)
    if data[offset] == 0xCE {
        return Some(CodePatternMatch {
            pattern_id: "x86-into-trap".to_string(),
            category: CodePatternKind::SoftwareTrap,
            mnemonic: "into".to_string(),
            offset,
            length: 1,
            bytes_hex: "CE".to_string(),
            section_name: None,
            relative_virtual_address: None,
            description: "Interrupt on overflow trap".to_string(),
            risk_alert: None,
        });
    }

    // 7. Indirect Branches and Stack Pivots
    // FF E4 (jmp rsp - Stack pivot / ROP trampoline gadget)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0xFF, 0xE4] {
        return Some(CodePatternMatch {
            pattern_id: "x86-jmp-rsp-pivot".to_string(),
            category: CodePatternKind::IndirectBranch,
            mnemonic: "jmp rsp".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Indirect jump to stack pointer (ROP trampoline / stack pivot gadget)"
                .to_string(),
            risk_alert: Some("JMP RSP stack pivot / shellcode bounce gadget detected".to_string()),
        });
    }

    // FF E0 (jmp rax)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0xFF, 0xE0] {
        return Some(CodePatternMatch {
            pattern_id: "x86-jmp-rax".to_string(),
            category: CodePatternKind::IndirectBranch,
            mnemonic: "jmp rax".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Indirect register jump to RAX".to_string(),
            risk_alert: None,
        });
    }

    // FF D0 (call rax)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0xFF, 0xD0] {
        return Some(CodePatternMatch {
            pattern_id: "x86-call-rax".to_string(),
            category: CodePatternKind::IndirectBranch,
            mnemonic: "call rax".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Indirect register subroutine call to RAX".to_string(),
            risk_alert: None,
        });
    }

    // FF D2 (call rdx)
    if offset + 2 <= data.len() && data[offset..offset + 2] == [0xFF, 0xD2] {
        return Some(CodePatternMatch {
            pattern_id: "x86-call-rdx".to_string(),
            category: CodePatternKind::IndirectBranch,
            mnemonic: "call rdx".to_string(),
            offset,
            length: 2,
            bytes_hex: format_bytes_hex(&data[offset..offset + 2]),
            section_name: None,
            relative_virtual_address: None,
            description: "Indirect register subroutine call to RDX".to_string(),
            risk_alert: None,
        });
    }

    // FF 25 <disp32> (jmp qword ptr [rip + disp32] - IAT thunk jump)
    if offset + 6 <= data.len() && data[offset..offset + 2] == [0xFF, 0x25] {
        let disp_bytes: [u8; 4] = data[offset + 2..offset + 6].try_into().unwrap_or([0; 4]);
        let disp = i32::from_le_bytes(disp_bytes);
        return Some(CodePatternMatch {
            pattern_id: "x64-jmp-rip-disp32".to_string(),
            category: CodePatternKind::IndirectBranch,
            mnemonic: format!("jmp [rip + 0x{disp:X}]"),
            offset,
            length: 6,
            bytes_hex: format_bytes_hex(&data[offset..offset + 6]),
            section_name: None,
            relative_virtual_address: None,
            description: format!("RIP-relative indirect jump (displacement: 0x{disp:X})"),
            risk_alert: None,
        });
    }

    // FF 15 <disp32> (call qword ptr [rip + disp32] - Imported API call)
    if offset + 6 <= data.len() && data[offset..offset + 2] == [0xFF, 0x15] {
        let disp_bytes: [u8; 4] = data[offset + 2..offset + 6].try_into().unwrap_or([0; 4]);
        let disp = i32::from_le_bytes(disp_bytes);
        return Some(CodePatternMatch {
            pattern_id: "x64-call-rip-disp32".to_string(),
            category: CodePatternKind::IndirectBranch,
            mnemonic: format!("call [rip + 0x{disp:X}]"),
            offset,
            length: 6,
            bytes_hex: format_bytes_hex(&data[offset..offset + 6]),
            section_name: None,
            relative_virtual_address: None,
            description: format!(
                "RIP-relative indirect subroutine call (displacement: 0x{disp:X})"
            ),
            risk_alert: None,
        });
    }

    None
}
