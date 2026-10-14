// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::Result;
use crate::resources::inspect_resources_file;
use std::path::Path;

/// CLI handler for `bsentinel resources <file> [--json]`.
pub fn handle_resources(file: &Path, json: bool) -> Result<()> {
    let report = inspect_resources_file(file)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| {
                crate::error::SentinelError::InvalidFormat(format!(
                    "Failed to serialize JSON report: {e}"
                ))
            })?
        );
        return Ok(());
    }

    println!(
        "=== PE Resource Directory (.rsrc) Inspection: {} ===",
        file.display()
    );
    println!(
        "Has Resources    : {}",
        if report.has_resources { "YES" } else { "NO" }
    );
    if !report.has_resources {
        println!("No valid resource directory found in binary.");
        return Ok(());
    }

    println!("Resource RVA     : 0x{:08X}", report.resource_rva);
    println!(
        "Resource Size    : {} bytes (0x{:X})",
        report.resource_size, report.resource_size
    );
    println!("Total Resources  : {}", report.total_resources);

    // Type Breakdown
    println!("\n[Resource Type Breakdown]");
    println!("{:<22} {:>8}", "Type", "Count");
    println!("{:-<22} {:->8}", "", "");
    for (tname, count) in &report.type_counts {
        println!("{:<22} {:>8}", tname, count);
    }

    // Application Manifest Info
    if let Some(ref m) = report.manifest {
        println!("\n[Application Manifest (RT_MANIFEST)]");
        if let Some(ref id) = m.assembly_identity {
            println!(
                "  Identity       : {} v{} ({})",
                id.name.as_deref().unwrap_or("unknown"),
                id.version.as_deref().unwrap_or("unknown"),
                id.processor_architecture.as_deref().unwrap_or("unknown")
            );
        }
        let uac = m
            .requested_execution_level
            .as_deref()
            .unwrap_or("Not Specified");
        println!("  UAC Level      : {uac}");
        if let Some(ui) = m.ui_access {
            println!("  UIAccess       : {ui}");
        }
        if let Some(ae) = m.auto_elevate {
            println!("  AutoElevate    : {ae}");
        }
    }

    // Version Information
    if let Some(ref v) = report.version_info {
        println!("\n[Version Information (RT_VERSION)]");
        if let Some(ref fv) = v.file_version {
            println!("  File Version   : {fv}");
        }
        if let Some(ref pv) = v.product_version {
            println!("  Product Version: {pv}");
        }
        if let Some(ref cn) = v.company_name {
            println!("  Company Name   : {cn}");
        }
        if let Some(ref fd) = v.file_description {
            println!("  File Desc      : {fd}");
        }
        if let Some(ref pn) = v.product_name {
            println!("  Product Name   : {pn}");
        }
        if let Some(ref cr) = v.legal_copyright {
            println!("  Copyright      : {cr}");
        }
    }

    // High Entropy Resources
    if !report.high_entropy_resources.is_empty() {
        println!("\n[Suspicious High-Entropy Resources]");
        println!(
            "{:<18} {:<12} {:>8} {:>8}  RVA",
            "Type", "Name", "Size", "Entropy"
        );
        println!("{:-<18} {:-<12} {:->8} {:->8}  {:-<10}", "", "", "", "", "");
        for item in &report.high_entropy_resources {
            println!(
                "{:<18} {:<12} {:>8} {:>8.2}  0x{:08X}",
                item.type_name, item.resource_name, item.size, item.entropy, item.rva
            );
        }
    }

    // Security & Forensic Alerts
    if !report.alerts.is_empty() {
        println!("\n[Security & Forensic Alerts]");
        for alert in &report.alerts {
            println!("  ! {alert}");
        }
    }

    Ok(())
}
