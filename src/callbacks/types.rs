// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Metadata and resolved information for an individual TLS callback entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsCallbackEntry {
    /// 0-indexed position within the callback array.
    pub index: usize,
    /// Absolute virtual address (VA) stored in the callback pointer array.
    pub callback_va: u64,
    /// Relative virtual address (RVA) within the image.
    pub callback_rva: u32,
    /// Raw physical file offset if mapped to a section on disk.
    pub file_offset: Option<usize>,
    /// Name of the containing section (e.g. ".text", ".tls", ".rdata").
    pub section_name: Option<String>,
    /// Whether the target section has executable memory permissions.
    pub is_executable: bool,
    /// Whether the target section has writable memory permissions.
    pub is_writable: bool,
    /// Whether the target section has RWX (Read-Write-Execute) permissions.
    pub is_rwx: bool,
    /// Specific anomaly or security warning for this callback if detected.
    pub anomaly: Option<String>,
}

/// Inspection summary for the PE TLS Directory (`IMAGE_DIRECTORY_ENTRY_TLS`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TlsDirectoryInfo {
    /// Whether a valid TLS directory entry is declared in the Optional Header.
    pub present: bool,
    /// RVA of the TLS directory header structure.
    pub directory_rva: u32,
    /// Size in bytes of the TLS directory entry.
    pub directory_size: u32,
    /// VA of the starting address of the raw TLS template data.
    pub start_address_of_raw_data: u64,
    /// VA of the ending address of the raw TLS template data.
    pub end_address_of_raw_data: u64,
    /// VA of the location to receive the TLS index.
    pub address_of_index: u64,
    /// VA of the null-terminated array of callback function pointers.
    pub address_of_callbacks: u64,
    /// RVA of the callback array if successfully translated.
    pub callbacks_rva: Option<u32>,
    /// Size in bytes of zero-fill template padding.
    pub size_of_zero_fill: u32,
    /// Characteristics flags.
    pub characteristics: u32,
    /// Resolved array of TLS callback functions.
    pub callbacks: Vec<TlsCallbackEntry>,
}

/// Unwind information summary parsed from an x64 `UNWIND_INFO` structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UnwindInfoSummary {
    /// Version of the unwind info structure (typically 1 or 2).
    pub version: u8,
    /// Raw flags byte from the header.
    pub flags: u8,
    /// Human-readable flag labels (e.g. "EHANDLER", "UHANDLER", "CHAININFO").
    pub flag_names: Vec<String>,
    /// Size of the function prolog in bytes.
    pub prolog_size: u8,
    /// Count of 16-bit unwind code slots.
    pub code_count: u8,
    /// Non-volatile frame register index if used (e.g. 5 for RBP).
    pub frame_register: u8,
    /// Scaled frame register offset.
    pub frame_offset: u8,
    /// Whether an exception handler RVA is declared.
    pub has_handler: bool,
    /// Relative virtual address (RVA) of the exception handler routine.
    pub handler_rva: Option<u32>,
    /// Name of containing section for the exception handler routine.
    pub handler_section: Option<String>,
    /// Whether the exception handler routine resides in executable memory.
    pub handler_executable: bool,
    /// Whether the exception handler routine resides in writable memory.
    pub handler_writable: bool,
    /// Whether this function chains to an earlier runtime function.
    pub is_chained: bool,
}

/// A single x64 runtime function entry parsed from `.pdata` (`RUNTIME_FUNCTION`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeFunctionEntry {
    /// 0-indexed entry number in the exception table.
    pub index: usize,
    /// RVA of the function start.
    pub begin_rva: u32,
    /// RVA of the function end.
    pub end_rva: u32,
    /// Calculated function span in bytes (`end_rva - begin_rva`).
    pub length: u32,
    /// RVA pointing to the associated `UNWIND_INFO` structure.
    pub unwind_info_rva: u32,
    /// Containing section name for the function body.
    pub section_name: Option<String>,
    /// Detailed unwind metadata if successfully parsed.
    pub unwind_info: Option<UnwindInfoSummary>,
    /// Detected anomaly or integrity issue (e.g. inverted bounds, missing handler).
    pub anomaly: Option<String>,
}

/// Inspection summary for the PE Exception Directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExceptionDirectoryInfo {
    /// Whether an exception directory is present.
    pub present: bool,
    /// RVA of the exception directory table (`.pdata`).
    pub directory_rva: u32,
    /// Size in bytes of the exception table.
    pub directory_size: u32,
    /// Total number of 12-byte `RUNTIME_FUNCTION` entries indicated by table size.
    pub total_functions: usize,
    /// Number of function entries parsed and validated.
    pub parsed_functions: usize,
    /// Number of function entries with custom exception or termination handlers.
    pub functions_with_handlers: usize,
    /// Parsed function entries.
    pub functions: Vec<RuntimeFunctionEntry>,
}

/// High-level executive statistics and risk indicators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CallbacksSummary {
    /// Total number of TLS callbacks detected.
    pub tls_callback_count: usize,
    /// Total number of x64 runtime functions parsed.
    pub pdata_function_count: usize,
    /// Total number of exception handlers identified.
    pub pdata_handler_count: usize,
    /// True if TLS callbacks exist that run prior to the main entry point.
    pub has_pre_main_execution: bool,
    /// Count of security anomalies or structural corruptions detected.
    pub anomalies_detected: usize,
}

/// Comprehensive inspection report returned by the callbacks analyzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallbacksReport {
    /// Input file path inspected.
    pub file_path: String,
    /// PE image format (e.g. "PE32+", "PE32").
    pub format: String,
    /// Preferred ImageBase address.
    pub image_base: u64,
    /// Entry point RVA (`AddressOfEntryPoint`).
    pub entry_point_rva: u32,
    /// TLS directory and callback details.
    pub tls: TlsDirectoryInfo,
    /// Exception directory and unwind table details.
    pub exceptions: ExceptionDirectoryInfo,
    /// High-level summary metrics.
    pub summary: CallbacksSummary,
    /// Forensic alerts and security warnings.
    pub alerts: Vec<String>,
}
