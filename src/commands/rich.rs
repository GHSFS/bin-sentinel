// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::path::Path;

use crate::error::Result;
use crate::rich::parse_rich_file;

/// Handles the `bsentinel rich <file> [--json]` subcommand.
pub fn handle_rich(file: &Path, json_output: bool) -> Result<()> {
    let report = parse_rich_file(file)?;

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| crate::error::SentinelError::InvalidFormat(e.to_string()))?;
        println!("{json_str}");
        return Ok(());
    }

    println!(
        "=== PE Rich Header Forensic Inspection: {} ===",
        file.display()
    );
    println!(
        "Location         : 0x{:04X} .. 0x{:04X} ({} bytes)",
        report.dans_offset,
        report.rich_offset + 8,
        report.header_size
    );
    println!("Primary Toolset  : {}", report.primary_toolchain);
    println!("XOR Decrypt Key  : 0x{:08X}", report.xor_key);

    let chk_str = if report.checksum.is_valid {
        format!(
            "VALID (Matches calculated 0x{:08X})",
            report.checksum.calculated_key
        )
    } else {
        format!(
            "MISMATCH (Stored: 0x{:08X}, Calculated: 0x{:08X})",
            report.checksum.stored_xor_key, report.checksum.calculated_key
        )
    };
    println!("Checksum Status  : {chk_str}");
    println!("Clear Data MD5   : {}", report.hashes.md5);
    println!("Clear Data SHA256: {}", report.hashes.sha256);
    println!();

    println!(
        "[Decoded Compilation Units & Tools ({} entries)]",
        report.record_count
    );
    println!(
        "{:<3} {:<18} {:<18} {:<8} {:<8} {:<7} Visual Studio Target",
        "#", "Tool Component", "Category", "ProdID", "Build", "Count"
    );
    println!("{}", "-".repeat(90));

    for (idx, r) in report.records.iter().enumerate() {
        println!(
            "{:<3} {:<18} {:<18} 0x{:04X}   {:<8} {:<7} {}",
            idx + 1,
            r.tool_name,
            r.tool_kind.to_string(),
            r.product_id,
            r.build_number,
            r.count,
            r.vs_version
        );
    }

    if !report.anomalies.is_empty() {
        println!();
        println!("[Anomalies & Security Warnings]");
        for anomaly in &report.anomalies {
            println!("  [!] {anomaly}");
        }
    }

    Ok(())
}
