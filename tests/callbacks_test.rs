// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use bin_sentinel::callbacks::{
    build_synthetic_callbacks_pe, inspect_callbacks_bytes, inspect_callbacks_file, CallbacksReport,
    SyntheticCallbacksSpec, SyntheticPdataSpec, UNW_FLAG_EHANDLER,
};
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_reject_or_empty_on_pe_without_callbacks_or_pdata() {
    let spec = SyntheticCallbacksSpec {
        include_tls: false,
        tls_callbacks: Vec::new(),
        tls_is_rwx: false,
        include_pdata: false,
        pdata_functions: Vec::new(),
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_clean.exe").expect("parse failed");

    assert!(report.format.contains("PE32+"));
    assert!(!report.tls.present);
    assert!(!report.exceptions.present);
    assert_eq!(report.summary.tls_callback_count, 0);
    assert_eq!(report.summary.pdata_function_count, 0);
    assert_eq!(report.summary.pdata_handler_count, 0);
    assert!(!report.summary.has_pre_main_execution);
}

#[test]
fn test_parse_synthetic_pe_with_valid_tls_callbacks() {
    let spec = SyntheticCallbacksSpec {
        include_tls: true,
        tls_callbacks: vec![0x0000_0001_4000_1020], // in .text
        tls_is_rwx: false,
        include_pdata: false,
        pdata_functions: Vec::new(),
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_tls.exe").expect("parse failed");

    assert!(report.tls.present);
    assert_eq!(report.tls.directory_rva, 0x3000);
    assert_eq!(report.tls.callbacks.len(), 1);
    assert_eq!(report.summary.tls_callback_count, 1);
    assert!(report.summary.has_pre_main_execution);

    let cb = &report.tls.callbacks[0];
    assert_eq!(cb.index, 0);
    assert_eq!(cb.callback_va, 0x0000_0001_4000_1020);
    assert_eq!(cb.callback_rva, 0x1020);
    assert_eq!(cb.section_name.as_deref(), Some(".text"));
    assert!(cb.is_executable);
    assert!(!cb.is_writable);
    assert!(!cb.is_rwx);
    assert!(cb.anomaly.is_none());

    // Should generate pre-main execution alert
    assert!(report
        .alerts
        .iter()
        .any(|a| a.contains("Pre-main execution hook")));
}

#[test]
fn test_parse_synthetic_pe_with_pdata_exception_table() {
    let spec = SyntheticCallbacksSpec {
        include_tls: false,
        tls_callbacks: Vec::new(),
        tls_is_rwx: false,
        include_pdata: true,
        pdata_functions: vec![SyntheticPdataSpec {
            begin_rva: 0x1000,
            end_rva: 0x1050,
            flags: UNW_FLAG_EHANDLER,
            has_handler: true,
            handler_rva: 0x1030, // in .text
        }],
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_pdata.exe").expect("parse failed");

    assert!(report.exceptions.present);
    assert_eq!(report.exceptions.directory_rva, 0x2000);
    assert_eq!(report.exceptions.total_functions, 1);
    assert_eq!(report.exceptions.functions_with_handlers, 1);
    assert_eq!(report.summary.pdata_function_count, 1);
    assert_eq!(report.summary.pdata_handler_count, 1);

    let func = &report.exceptions.functions[0];
    assert_eq!(func.begin_rva, 0x1000);
    assert_eq!(func.end_rva, 0x1050);
    assert_eq!(func.length, 0x50);
    assert_eq!(func.section_name.as_deref(), Some(".text"));
    assert!(func.anomaly.is_none());

    let unwind = func.unwind_info.as_ref().expect("unwind info missing");
    assert_eq!(unwind.version, 1);
    assert_eq!(unwind.flags, UNW_FLAG_EHANDLER);
    assert!(unwind.has_handler);
    assert_eq!(unwind.handler_rva, Some(0x1030));
    assert_eq!(unwind.handler_section.as_deref(), Some(".text"));
    assert!(unwind.handler_executable);
    assert!(!unwind.handler_writable);
}

#[test]
fn test_detect_tls_rwx_anomaly() {
    // Put callback targeting .data (at 0x3010) with rwx_tls enabled
    let spec = SyntheticCallbacksSpec {
        include_tls: true,
        tls_callbacks: vec![0x0000_0001_4000_3010],
        tls_is_rwx: true,
        include_pdata: false,
        pdata_functions: Vec::new(),
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_rwx.exe").expect("parse failed");

    assert_eq!(report.tls.callbacks.len(), 1);
    let cb = &report.tls.callbacks[0];
    assert!(cb.is_rwx);
    assert!(cb.anomaly.is_some());
    assert!(cb.anomaly.as_ref().unwrap().contains("RWX"));
    assert!(report.alerts.iter().any(|a| a.contains("RWX section")));
}

#[test]
fn test_detect_inverted_or_zero_pdata_span() {
    let spec = SyntheticCallbacksSpec {
        include_tls: false,
        tls_callbacks: Vec::new(),
        tls_is_rwx: false,
        include_pdata: true,
        pdata_functions: vec![SyntheticPdataSpec {
            begin_rva: 0x1050,
            end_rva: 0x1000, // inverted!
            flags: 0,
            has_handler: false,
            handler_rva: 0,
        }],
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_inverted.exe").expect("parse failed");

    assert_eq!(report.exceptions.functions.len(), 1);
    let func = &report.exceptions.functions[0];
    assert!(func.anomaly.is_some());
    assert!(func.anomaly.as_ref().unwrap().contains("Inverted"));
    assert!(report
        .alerts
        .iter()
        .any(|a| a.contains("inverted/zero span")));
}

#[test]
fn test_detect_abnormal_exception_handler_in_unmapped_memory() {
    let spec = SyntheticCallbacksSpec {
        include_tls: false,
        tls_callbacks: Vec::new(),
        tls_is_rwx: false,
        include_pdata: true,
        pdata_functions: vec![SyntheticPdataSpec {
            begin_rva: 0x1000,
            end_rva: 0x1050,
            flags: UNW_FLAG_EHANDLER,
            has_handler: true,
            handler_rva: 0x9999_0000, // unmapped
        }],
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_bad_handler.exe").expect("parse failed");

    assert_eq!(report.exceptions.functions.len(), 1);
    let func = &report.exceptions.functions[0];
    let unwind = func.unwind_info.as_ref().expect("unwind info missing");
    assert_eq!(unwind.handler_section, None);
    assert!(!unwind.handler_executable);
    assert!(report
        .alerts
        .iter()
        .any(|a| a.contains("exception handler targets unmapped RVA")));
}

#[test]
fn test_multiple_tls_callbacks_sequential() {
    let spec = SyntheticCallbacksSpec {
        include_tls: true,
        tls_callbacks: vec![
            0x0000_0001_4000_1020,
            0x0000_0001_4000_1024,
            0x0000_0001_4000_1028,
        ],
        tls_is_rwx: false,
        include_pdata: false,
        pdata_functions: Vec::new(),
    };
    let data = build_synthetic_callbacks_pe(&spec);
    let report = inspect_callbacks_bytes(&data, "synthetic_multi_cb.exe").expect("parse failed");

    assert_eq!(report.tls.callbacks.len(), 3);
    assert_eq!(report.tls.callbacks[0].index, 0);
    assert_eq!(report.tls.callbacks[1].index, 1);
    assert_eq!(report.tls.callbacks[2].index, 2);
    assert_eq!(report.tls.callbacks[0].callback_rva, 0x1020);
    assert_eq!(report.tls.callbacks[1].callback_rva, 0x1024);
    assert_eq!(report.tls.callbacks[2].callback_rva, 0x1028);
}

#[test]
fn test_malformed_and_truncated_callbacks_resilience() {
    // Truncated buffer
    let mut data = build_synthetic_callbacks_pe(&SyntheticCallbacksSpec::default());
    data.truncate(data.len() / 2);
    let res = inspect_callbacks_bytes(&data, "truncated.exe");
    assert!(res.is_err() || res.unwrap().tls.callbacks.is_empty());

    // Empty buffer
    assert!(inspect_callbacks_bytes(&[], "empty.exe").is_err());

    // Random non-PE buffer
    let random_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    assert!(inspect_callbacks_bytes(&random_bytes, "random.exe").is_err());
}

#[test]
fn test_real_windows_binary_callbacks_if_available() {
    let candidates = [
        r"C:\Windows\System32\ntdll.dll",
        r"C:\Windows\System32\kernel32.dll",
    ];

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            let report =
                inspect_callbacks_file(path).expect("failed to inspect real system binary");
            assert!(report.format.contains("PE32+"));
            assert!(report.exceptions.present);
            assert!(report.exceptions.total_functions > 10);
            println!(
                "Successfully parsed real binary {}: {} exception functions, {} TLS callbacks",
                path,
                report.exceptions.total_functions,
                report.tls.callbacks.len()
            );
            break;
        }
    }
}

#[test]
fn test_cli_callbacks_subcommand_json_and_table() {
    let spec = SyntheticCallbacksSpec::default();
    let data = build_synthetic_callbacks_pe(&spec);

    let temp_file = NamedTempFile::new().expect("failed to create temp file");
    std::fs::write(temp_file.path(), &data).expect("failed to write temp file");

    let bin_path = env!("CARGO_BIN_EXE_bsentinel");

    // 1. Test table mode
    let output_table = Command::new(bin_path)
        .arg("callbacks")
        .arg(temp_file.path())
        .output()
        .expect("failed to run bsentinel callbacks");
    assert!(
        output_table.status.success(),
        "Table command failed: {}",
        String::from_utf8_lossy(&output_table.stderr)
    );
    let stdout_table = String::from_utf8_lossy(&output_table.stdout);
    assert!(stdout_table.contains("PE TLS Callbacks & Exception Unwind (.pdata) Inspection"));
    assert!(stdout_table.contains("TLS Directory (IMAGE_DIRECTORY_ENTRY_TLS)"));
    assert!(stdout_table.contains("Exception Directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION"));

    // 2. Test JSON mode
    let output_json = Command::new(bin_path)
        .arg("callbacks")
        .arg(temp_file.path())
        .arg("--json")
        .output()
        .expect("failed to run bsentinel callbacks --json");
    assert!(
        output_json.status.success(),
        "JSON command failed: {}",
        String::from_utf8_lossy(&output_json.stderr)
    );
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    let parsed: CallbacksReport =
        serde_json::from_str(&stdout_json).expect("failed to parse JSON output");
    assert!(parsed.tls.present);
    assert!(parsed.exceptions.present);
    assert_eq!(parsed.summary.tls_callback_count, 1);
    assert_eq!(parsed.summary.pdata_function_count, 1);
}
