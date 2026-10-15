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
    /// Inspect macOS/iOS Mach-O 64-bit and Universal (Fat) binary headers, segments, sections, and mitigations.
    InspectMacho {
        /// Target Mach-O binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Generate a deterministic synthetic Mach-O sample binary (64-bit or Universal) for forensic testing.
    SynthMacho {
        /// Output path for the synthetic Mach-O executable.
        output: PathBuf,
        /// Generate a Universal (Fat) binary containing both x86_64 and ARM64 slices.
        #[arg(long)]
        universal: bool,
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
    /// Scan executable code sections for x86_64 prologues, direct syscalls, and anti-debug patterns.
    ScanCode {
        /// Target binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Scan binary files using declarative YARA-style hex signatures with wildcards, byte jumps, or JSON rule files.
    RuleScan {
        /// Target binary file path.
        file: PathBuf,
        /// Ad-hoc hex pattern with wildcards and jumps (e.g. "48 83 EC ?? [2-6] E8").
        #[arg(long, short = 'p')]
        pattern: Option<String>,
        /// Path to declarative JSON rule file.
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Inspect PE Authenticode digital signatures, certificate tables, True digest, and EOF overlays.
    SigCheck {
        /// Target PE binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Compare two binary files and generate structural byte/section diffs and patch recipes.
    Diff {
        /// Original (baseline) binary file path.
        original: PathBuf,
        /// Modified (target) binary file path.
        modified: PathBuf,
        /// Optional path to export declarative JSON patch recipe.
        #[arg(long)]
        out_recipe: Option<PathBuf>,
        /// Output structured JSON diff report.
        #[arg(long)]
        json: bool,
    },
    /// Apply or reverse a declarative JSON patch recipe against a target binary file.
    ApplyRecipe {
        /// Target binary file path to patch.
        file: PathBuf,
        /// Path to declarative JSON patch recipe file.
        recipe: PathBuf,
        /// Perform dry-run verification without writing changes to disk.
        #[arg(long)]
        dry_run: bool,
        /// Reverse the patch operations (swap expected and replacement bytes).
        #[arg(long)]
        reverse: bool,
        /// Create a `.bak` backup file prior to applying modifications.
        #[arg(long)]
        backup: bool,
        /// Output structured JSON apply report.
        #[arg(long)]
        json: bool,
    },
    /// Decode PE Rich header, compiler toolchain @comp.id product IDs, and verify 32-bit checksum.
    Rich {
        /// Target PE binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Brute-force XOR, ADD, and ROL deobfuscation to uncover hidden URLs, IPv4 addresses, Registry keys, and PE headers.
    XorScan {
        /// Target binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Parse 3-level PE resource directory (.rsrc), extract application manifest, UAC execution levels, and version strings.
    Resources {
        /// Target PE binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Parse PE TLS callback directory and x64 exception unwind (.pdata) tables to detect pre-main hooks and abnormal handlers.
    Callbacks {
        /// Target PE binary file path.
        file: PathBuf,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Detect, decode, and score embedded Base64, URL-safe Base64, and hex-encoded payloads.
    Carve {
        /// Target binary file or script path.
        file: PathBuf,
        /// Minimum length of encoded string to carve (default: 16).
        #[arg(long, default_value = "16")]
        min_len: usize,
        /// Optional directory to safely extract decoded payloads to disk.
        #[arg(long)]
        extract_dir: Option<PathBuf>,
        /// Output structured JSON report.
        #[arg(long)]
        json: bool,
    },
}
