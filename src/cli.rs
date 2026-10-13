// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Zero-dependency binary forensics, PE static analyzer, entropy packer detector, and declarative byte-patching toolkit.
#[derive(Debug, Parser)]
#[command(
    name = "bsentinel",
    version,
    about = "Zero-dependency binary forensics, PE static analyzer, packer entropy detector & declarative byte-patching CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Inspect PE32/PE32+ headers, security mitigations (ASLR/DEP/CFG), section entropy, and packer anomalies.
    Inspect {
        /// Target binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Compute overall and sliding-window Shannon entropy, Chi-square uniformity, and byte classification.
    Entropy {
        /// Target binary file path.
        file: PathBuf,
        /// Sliding window size in bytes.
        #[arg(long, default_value_t = 4096)]
        window: usize,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Extract printable ASCII and UTF-16LE strings and highlight Indicators of Compromise (IoCs).
    Strings {
        /// Target binary file path.
        file: PathBuf,
        /// Minimum string length to extract.
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        /// Filter output to only strings matching IoC patterns (URLs, IPv4, Registry keys, Win32 injection APIs).
        #[arg(long)]
        ioc_only: bool,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Apply a verified declarative byte patch at a target file offset with SHA-256 verification.
    Patch {
        /// Target binary file path.
        file: PathBuf,
        /// File byte offset in hex (e.g. 0x100) or decimal.
        #[arg(long)]
        offset: String,
        /// Expected original hex bytes at offset (aborts with PatchMismatch if different).
        #[arg(long)]
        expect: String,
        /// Replacement hex bytes (must match expected byte length).
        #[arg(long)]
        replace: String,
        /// Create a `.bak` backup file prior to patching.
        #[arg(long)]
        backup: bool,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Generate a deterministic synthetic PE32+ (64-bit) sample binary for forensic testing.
    SynthPe {
        /// Output path for the synthetic PE64 executable.
        output: PathBuf,
    },
    /// Inspect Linux/BSD ELF64 headers, security mitigations (PIE/RELRO/NX/Canary), dynamic tags, and symbol tables.
    InspectElf {
        /// Target ELF binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Generate a deterministic synthetic ELF64 sample binary for forensic testing.
    SynthElf {
        /// Output path for the synthetic ELF64 executable.
        output: PathBuf,
    },
    /// Scan binary files for embedded cryptographic constants, S-Boxes, round keys, and lookup tables.
    CryptoScan {
        /// Target binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Parse PE Import Directory (IAT/ILT), Export Directory (EAT), imphash, and resolve dynamic API hashes.
    Imports {
        /// Target PE binary file path.
        file: PathBuf,
        /// Optional API hash (in hex, e.g. 0xEDB88320 or EDB88320) to resolve against known Windows APIs.
        #[arg(long)]
        resolve_hash: Option<String>,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
}
