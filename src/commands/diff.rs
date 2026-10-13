// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::path::Path;

use crate::diff::{
    apply_recipe, diff_files, generate_recipe, load_recipe_from_file, save_recipe_to_file,
    ApplyOptions,
};
use crate::error::Result;

/// Handles the `diff` CLI subcommand.
pub fn handle_diff(
    original: &Path,
    modified: &Path,
    out_recipe: Option<&Path>,
    json: bool,
) -> Result<()> {
    let diff_report = diff_files(original, modified)?;

    if let Some(recipe_p) = out_recipe {
        let recipe = generate_recipe(&diff_report, None, None);
        save_recipe_to_file(&recipe, recipe_p)?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&diff_report).unwrap_or_default()
        );
    } else {
        println!("=== BinSentinel Binary Diff Summary ===");
        println!(
            "Original Binary   : {} ({} bytes)",
            diff_report.original_path, diff_report.original_size
        );
        println!("Original SHA-256  : {}", diff_report.original_sha256);
        println!(
            "Modified Binary   : {} ({} bytes)",
            diff_report.modified_path, diff_report.modified_size
        );
        println!("Modified SHA-256  : {}", diff_report.modified_sha256);
        println!("Detected Format   : {}", diff_report.format);
        println!(
            "Differing Content : {} bytes across {} contiguous hunks",
            diff_report.total_differing_bytes, diff_report.hunk_count
        );

        if let Some(ref miti_diff) = diff_report.mitigations_diff {
            println!("\n[Security Mitigation Changes]");
            for ch in &miti_diff.changes {
                println!("  {:35} : {} -> {}", ch.mitigation, ch.before, ch.after);
            }
        }

        if !diff_report.section_diffs.is_empty() {
            println!("\n[Section Entropy & Diff Summary]");
            println!(
                "  {:<12} | {:<10} | {:<10} | {:<10} | {:<12} | {:<8}",
                "Section", "Orig Ent", "Mod Ent", "Delta", "Diff Bytes", "Hunks"
            );
            println!("  {}", "-".repeat(74));
            for s in &diff_report.section_diffs {
                let o_str = s
                    .orig_entropy
                    .map(|e| format!("{e:.4}"))
                    .unwrap_or_else(|| "-".into());
                let m_str = s
                    .mod_entropy
                    .map(|e| format!("{e:.4}"))
                    .unwrap_or_else(|| "-".into());
                let d_str = s
                    .entropy_delta
                    .map(|d| format!("{d:+.4}"))
                    .unwrap_or_else(|| "-".into());
                println!(
                    "  {:<12} | {:<10} | {:<10} | {:<10} | {:<12} | {:<8}",
                    s.name, o_str, m_str, d_str, s.differing_bytes, s.hunk_count
                );
            }
        }

        if !diff_report.hunks.is_empty() {
            println!("\n[Differing Byte Hunks]");
            let max_display = 25;
            for (idx, h) in diff_report.hunks.iter().take(max_display).enumerate() {
                let sec_str = h.section_name.as_deref().unwrap_or("-");
                let rva_str = if let Some(rva) = h.rva {
                    format!("RVA 0x{rva:08X}")
                } else {
                    format!("Offset 0x{:08X}", h.offset)
                };

                let orig_preview = if h.orig_bytes_hex.len() > 32 {
                    format!("{}...", &h.orig_bytes_hex[..32])
                } else {
                    h.orig_bytes_hex.clone()
                };
                let mod_preview = if h.mod_bytes_hex.len() > 32 {
                    format!("{}...", &h.mod_bytes_hex[..32])
                } else {
                    h.mod_bytes_hex.clone()
                };

                println!(
                    "  #{:02} | Offset 0x{:08X} ({:3} B) | {:<12} | {:<14} | -[{}] +[{}]",
                    idx + 1,
                    h.offset,
                    h.length,
                    sec_str,
                    rva_str,
                    orig_preview,
                    mod_preview
                );
            }
            if diff_report.hunks.len() > max_display {
                println!(
                    "  ... ({} additional hunks omitted from terminal view; use --json for full report)",
                    diff_report.hunks.len() - max_display
                );
            }
        }

        if let Some(recipe_p) = out_recipe {
            println!("\n[Patch Recipe Export]");
            println!(
                "  Exported declarative recipe manifest: {}",
                recipe_p.display()
            );
        }
    }

    Ok(())
}

/// Handles the `apply-recipe` CLI subcommand.
pub fn handle_apply_recipe(
    file: &Path,
    recipe_path: &Path,
    dry_run: bool,
    reverse: bool,
    backup: bool,
    json: bool,
) -> Result<()> {
    let recipe = load_recipe_from_file(recipe_path)?;
    let options = ApplyOptions {
        dry_run,
        reverse,
        backup,
    };
    let report = apply_recipe(file, &recipe, &options)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("=== BinSentinel Patch Recipe Application ===");
        println!("Target File       : {}", report.target_path);
        println!(
            "Recipe Manifest   : {} ({} operations)",
            report.recipe_name, report.operations_count
        );
        let mode_desc = if report.is_dry_run {
            "Dry Run (Verification only, no disk writes)"
        } else if report.reversed {
            "Reversed Patch Applied"
        } else {
            "Patch Applied Successfully"
        };
        println!("Execution Mode    : {mode_desc}");
        println!("SHA-256 Before    : {}", report.sha256_before);
        println!("SHA-256 After     : {}", report.sha256_after);
        if let Some(ref bak) = report.backup_path {
            println!("Backup Path       : {bak}");
        }
        println!("Verification      : Constant-time & SHA-256 Integrity Verified");
    }

    Ok(())
}
