// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::callbacks::inspect_callbacks_file;
use crate::error::Result;
use std::path::Path;

/// CLI handler for `bsentinel callbacks <file> [--json]`.
pub fn handle_callbacks(file: &Path, json: bool) -> Result<()> {
    let report = inspect_callbacks_file(file)?;

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
        "=== PE TLS Callbacks & Exception Unwind (.pdata) Inspection: {} ===",
        file.display()
    );
    println!("Format           : {}", report.format);
    println!("ImageBase        : 0x{:016X}", report.image_base);
    println!("EntryPoint RVA   : 0x{:08X}", report.entry_point_rva);

    // 1. TLS Directory & Callbacks
    println!("\n[TLS Directory (IMAGE_DIRECTORY_ENTRY_TLS)]");
    println!(
        "  Present        : {}",
        if report.tls.present { "YES" } else { "NO" }
    );
    if report.tls.present {
        println!("  Directory RVA  : 0x{:08X}", report.tls.directory_rva);
        println!("  Directory Size : {} bytes", report.tls.directory_size);
        println!(
            "  Callbacks VA   : 0x{:016X}",
            report.tls.address_of_callbacks
        );
        if let Some(rva) = report.tls.callbacks_rva {
            println!("  Callbacks RVA  : 0x{rva:08X}");
        }
        println!("  Total Callbacks: {}", report.tls.callbacks.len());

        if !report.tls.callbacks.is_empty() {
            println!("\n  [TLS Callback Execution Hooks]");
            println!(
                "  {:<6} {:<18} {:<12} {:<10} {:<8} Status",
                "Index", "Callback VA", "RVA", "Section", "Perms"
            );
            println!(
                "  {:-<6} {:-<18} {:-<12} {:-<10} {:-<8} {:-<20}",
                "", "", "", "", "", ""
            );
            for cb in &report.tls.callbacks {
                let perms = if cb.is_rwx {
                    "RWX"
                } else if cb.is_executable {
                    "RX"
                } else if cb.is_writable {
                    "RW"
                } else {
                    "RO"
                };
                let status = cb.anomaly.as_deref().unwrap_or("Valid / Pre-Main Hook");
                println!(
                    "  {:<6} 0x{:016X} 0x{:08X}   {:<10} {:<8} {}",
                    cb.index,
                    cb.callback_va,
                    cb.callback_rva,
                    cb.section_name.as_deref().unwrap_or("??"),
                    perms,
                    status
                );
            }
        }
    }

    // 2. Exception Directory (.pdata)
    println!("\n[Exception Directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION / .pdata)]");
    println!(
        "  Present        : {}",
        if report.exceptions.present {
            "YES"
        } else {
            "NO"
        }
    );
    if report.exceptions.present {
        println!(
            "  Directory RVA  : 0x{:08X}",
            report.exceptions.directory_rva
        );
        println!(
            "  Directory Size : {} bytes",
            report.exceptions.directory_size
        );
        println!("  Total Functions: {}", report.exceptions.total_functions);
        println!(
            "  With Handlers  : {}",
            report.exceptions.functions_with_handlers
        );

        if !report.exceptions.functions.is_empty() {
            println!("\n  [Sample Runtime Functions & Exception Handlers]");
            println!(
                "  {:<6} {:<23} {:<8} {:<12} {:<12} Flags",
                "Index", "Function Range (RVA)", "Length", "Section", "Handler RVA"
            );
            println!(
                "  {:-<6} {:-<23} {:-<8} {:-<12} {:-<12} {:-<16}",
                "", "", "", "", "", ""
            );

            // Display up to 16 function entries (or all if <= 16)
            for func in report.exceptions.functions.iter().take(16) {
                let range = format!("0x{:08X}..0x{:08X}", func.begin_rva, func.end_rva);
                let (handler_str, flags_str) = match func.unwind_info {
                    Some(ref u) => {
                        let h = match u.handler_rva {
                            Some(hrva) => format!("0x{hrva:08X}"),
                            None => "-".to_string(),
                        };
                        let f = u.flag_names.join("|");
                        (h, f)
                    }
                    None => ("-".to_string(), "-".to_string()),
                };

                println!(
                    "  {:<6} {:<23} {:<8} {:<12} {:<12} {}",
                    func.index,
                    range,
                    format!("{}B", func.length),
                    func.section_name.as_deref().unwrap_or("??"),
                    handler_str,
                    flags_str
                );
            }

            if report.exceptions.functions.len() > 16 {
                println!(
                    "  ... ({} additional runtime function entries omitted)",
                    report.exceptions.functions.len() - 16
                );
            }
        }
    }

    // 3. Security & Forensic Alerts
    if !report.alerts.is_empty() {
        println!("\n[Security & Forensic Alerts]");
        for alert in &report.alerts {
            println!("  ! {alert}");
        }
    }

    Ok(())
}
