// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod forensics;
pub mod inspect;
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
    }
}
