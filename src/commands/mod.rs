// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod authenticode;
pub mod callbacks;
pub mod carve;
pub mod diff;
pub mod forensics;
pub mod fuzzy;
pub mod inspect;
pub mod macho;
pub mod resources;
pub mod rich;
pub mod rules;

use crate::cli::Commands;
use crate::error::Result;

/// Dispatches high-level CLI commands to domain-specific handler modules.
pub fn dispatch(command: Commands) -> Result<()> {
    match command {
        Commands::Inspect { file, json } => inspect::handle_inspect(&file, json),
        Commands::Entropy { file, window, json } => inspect::handle_entropy(&file, window, json),
        Commands::Strings {
            file,
            min_len,
            ioc_only,
            json,
        } => inspect::handle_strings(&file, min_len, ioc_only, json),
        Commands::Patch {
            file,
            offset,
            expect,
            replace,
            backup,
            json,
        } => inspect::handle_patch(&file, &offset, &expect, &replace, backup, json),
        Commands::SynthPe { output } => inspect::handle_synth_pe(&output),
        Commands::InspectElf { file, json } => inspect::handle_inspect_elf(&file, json),
        Commands::SynthElf { output } => inspect::handle_synth_elf(&output),
        Commands::InspectMacho { file, json } => macho::handle_inspect_macho(&file, json),
        Commands::SynthMacho { output, universal } => macho::handle_synth_macho(&output, universal),
        Commands::CryptoScan { file, json } => forensics::handle_crypto_scan(&file, json),
        Commands::Imports {
            file,
            resolve_hash,
            json,
        } => forensics::handle_imports(&file, resolve_hash.as_deref(), json),
        Commands::ScanCode { file, json } => forensics::handle_scan_code(&file, json),
        Commands::RuleScan {
            file,
            pattern,
            rules: rules_path,
            json,
        } => rules::handle_rule_scan(&file, pattern.as_deref(), rules_path.as_deref(), json),
        Commands::SigCheck { file, json } => authenticode::handle_sig_check(&file, json),
        Commands::Diff {
            original,
            modified,
            out_recipe,
            json,
        } => diff::handle_diff(&original, &modified, out_recipe.as_deref(), json),
        Commands::ApplyRecipe {
            file,
            recipe,
            dry_run,
            reverse,
            backup,
            json,
        } => diff::handle_apply_recipe(&file, &recipe, dry_run, reverse, backup, json),
        Commands::Rich { file, json } => rich::handle_rich(&file, json),
        Commands::XorScan { file, json } => forensics::handle_xor_scan(&file, json),
        Commands::Resources { file, json } => resources::handle_resources(&file, json),
        Commands::Callbacks { file, json } => callbacks::handle_callbacks(&file, json),
        Commands::Carve {
            file,
            min_len,
            extract_dir,
            json,
        } => carve::handle_carve(&file, min_len, extract_dir.as_deref(), json),
        Commands::FuzzyHash { file, json } => fuzzy::handle_fuzzy_hash(&file, json),
        Commands::FuzzyCompare { file1, file2, json } => {
            fuzzy::handle_fuzzy_compare(&file1, &file2, json)
        }
    }
}
