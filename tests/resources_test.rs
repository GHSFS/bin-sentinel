// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use bin_sentinel::pe::build_synthetic_pe64;
use bin_sentinel::resources::{
    build_synthetic_resource_pe, inspect_resources_bytes, inspect_resources_file, ResourceReport,
    SyntheticResourceSpec,
};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

fn get_bin_path() -> PathBuf {
    let mut path = env::current_exe().expect("find current exe");
    path.pop(); // pop test name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("bsentinel");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

#[test]
fn test_reject_or_empty_on_pe_without_resources() {
    let pe_bytes = build_synthetic_pe64(&[]);
    let report = inspect_resources_bytes(&pe_bytes).expect("inspect PE without resources");
    assert!(!report.has_resources);
    assert_eq!(report.total_resources, 0);
    assert!(report.resources.is_empty());
    assert!(report.manifest.is_none());
    assert!(report.version_info.is_none());
}

#[test]
fn test_parse_synthetic_pe_resources_and_directory_tree() {
    let spec = SyntheticResourceSpec::default();
    let pe_bytes = build_synthetic_resource_pe(&spec);

    let report = inspect_resources_bytes(&pe_bytes).expect("inspect synthetic PE with resources");
    assert!(report.has_resources);
    assert_eq!(report.resource_rva, 0x2000);
    assert_eq!(report.total_resources, 3);

    assert_eq!(report.type_counts.get("RT_MANIFEST"), Some(&1));
    assert_eq!(report.type_counts.get("RT_VERSION"), Some(&1));
    assert_eq!(report.type_counts.get("RT_RCDATA"), Some(&1));

    let manifest_res = report
        .resources
        .iter()
        .find(|r| r.type_name == "RT_MANIFEST")
        .expect("RT_MANIFEST resource entry");
    assert_eq!(manifest_res.type_id, Some(24));
    assert_eq!(manifest_res.name_id, Some(1));
    assert_eq!(manifest_res.language_id, 0x0409);
    assert!(manifest_res.file_offset.is_some());
    assert!(manifest_res.size > 0);
}

#[test]
fn test_uac_require_administrator_manifest_detection() {
    let spec = SyntheticResourceSpec {
        uac_level: "requireAdministrator".to_string(),
        auto_elevate: true,
        product_name: "Test Administrator Probe".to_string(),
        file_version: "2.5.0.0".to_string(),
        include_high_entropy_rcdata: false,
    };
    let pe_bytes = build_synthetic_resource_pe(&spec);
    let report = inspect_resources_bytes(&pe_bytes).expect("inspect synthetic manifest");

    let manifest = report.manifest.expect("parsed manifest");
    assert_eq!(
        manifest.requested_execution_level.as_deref(),
        Some("requireAdministrator")
    );
    assert_eq!(manifest.ui_access, Some(false));
    assert_eq!(manifest.auto_elevate, Some(true));

    assert!(report
        .alerts
        .iter()
        .any(|a| a.contains("requireAdministrator")));
    assert!(report.alerts.iter().any(|a| a.contains("autoElevate")));
}

#[test]
fn test_uac_as_invoker_manifest() {
    let spec = SyntheticResourceSpec {
        uac_level: "asInvoker".to_string(),
        auto_elevate: false,
        product_name: "Test Standard User Utility".to_string(),
        file_version: "1.0.0.0".to_string(),
        include_high_entropy_rcdata: false,
    };
    let pe_bytes = build_synthetic_resource_pe(&spec);
    let report = inspect_resources_bytes(&pe_bytes).expect("inspect asInvoker manifest");

    let manifest = report.manifest.expect("parsed manifest");
    assert_eq!(
        manifest.requested_execution_level.as_deref(),
        Some("asInvoker")
    );
    assert_eq!(manifest.auto_elevate, Some(false));

    assert!(!report
        .alerts
        .iter()
        .any(|a| a.contains("requireAdministrator")));
}

#[test]
fn test_high_entropy_rcdata_payload_detection() {
    let spec = SyntheticResourceSpec {
        include_high_entropy_rcdata: true,
        ..Default::default()
    };
    let pe_bytes = build_synthetic_resource_pe(&spec);
    let report = inspect_resources_bytes(&pe_bytes).expect("inspect high-entropy rcdata");

    assert_eq!(report.high_entropy_resources.len(), 1);
    let flagged = &report.high_entropy_resources[0];
    assert_eq!(flagged.type_name, "RT_RCDATA");
    assert!(
        flagged.entropy >= 7.20,
        "Entropy should exceed threshold: got {}",
        flagged.entropy
    );

    let rcdata_entry = report
        .resources
        .iter()
        .find(|r| r.type_name == "RT_RCDATA")
        .expect("RCDATA entry");
    assert!(rcdata_entry.is_high_entropy);
}

#[test]
fn test_version_info_properties_extraction() {
    let spec = SyntheticResourceSpec {
        product_name: "BinSentinel Enterprise Engine".to_string(),
        file_version: "9.8.7.6".to_string(),
        ..Default::default()
    };
    let pe_bytes = build_synthetic_resource_pe(&spec);
    let report = inspect_resources_bytes(&pe_bytes).expect("inspect version info");

    let ver = report.version_info.expect("version info struct");
    assert_eq!(
        ver.product_name.as_deref(),
        Some("BinSentinel Enterprise Engine")
    );
    assert_eq!(ver.file_version.as_deref(), Some("9.8.7.6"));
    assert_eq!(ver.company_name.as_deref(), Some("GHSFS Engineering"));
}

#[test]
fn test_malformed_and_truncated_resource_directory_resilience() {
    let spec = SyntheticResourceSpec::default();
    let mut pe_bytes = build_synthetic_resource_pe(&spec);

    // Corrupt resource directory size
    if pe_bytes.len() > 0x1A0 {
        pe_bytes[0x180..0x184].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    // Should not panic or crash
    let _ = inspect_resources_bytes(&pe_bytes);

    // Truncate file mid-resource-directory
    let truncated = &pe_bytes[..pe_bytes.len().min(600)];
    let _ = inspect_resources_bytes(truncated);

    // Non-PE bytes
    let rand_bytes = vec![0x90; 1024];
    assert!(inspect_resources_bytes(&rand_bytes).is_err());
}

#[test]
fn test_cli_resources_subcommand_json_and_table() {
    let spec = SyntheticResourceSpec::default();
    let pe_bytes = build_synthetic_resource_pe(&spec);

    let mut tmp = NamedTempFile::new().expect("create tempfile");
    tmp.write_all(&pe_bytes).expect("write temp pe bytes");

    let bin_path = get_bin_path();
    if !bin_path.exists() {
        return;
    }

    // 1. Human-readable table output
    let output = Command::new(&bin_path)
        .arg("resources")
        .arg(tmp.path())
        .output()
        .expect("execute bsentinel resources");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== PE Resource Directory (.rsrc) Inspection:"));
    assert!(stdout.contains("RT_MANIFEST"));
    assert!(stdout.contains("RT_VERSION"));
    assert!(stdout.contains("RT_RCDATA"));
    assert!(stdout.contains("requireAdministrator"));

    // 2. Structured JSON output
    let json_output = Command::new(&bin_path)
        .arg("resources")
        .arg(tmp.path())
        .arg("--json")
        .output()
        .expect("execute bsentinel resources --json");

    assert!(json_output.status.success());
    let json_str = String::from_utf8_lossy(&json_output.stdout);
    let parsed: ResourceReport =
        serde_json::from_str(&json_str).expect("deserialize ResourceReport JSON");
    assert!(parsed.has_resources);
    assert_eq!(parsed.total_resources, 3);
    assert_eq!(
        parsed
            .manifest
            .as_ref()
            .and_then(|m| m.requested_execution_level.as_deref()),
        Some("requireAdministrator")
    );
}

#[test]
fn test_real_windows_system_binary_resources_if_available() {
    let cmd_path = Path::new(r"C:\Windows\System32\cmd.exe");
    if !cmd_path.exists() {
        return;
    }

    let report = inspect_resources_file(cmd_path).expect("inspect Windows cmd.exe resources");
    assert!(
        report.has_resources,
        "System cmd.exe should contain a valid resource directory"
    );
    assert!(
        report.total_resources > 0,
        "System cmd.exe should have resources"
    );
    assert!(
        report.type_counts.contains_key("RT_VERSION")
            || report.type_counts.contains_key("RT_MANIFEST"),
        "System cmd.exe should have either RT_VERSION or RT_MANIFEST"
    );
}
