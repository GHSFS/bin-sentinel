// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! PE Rich Header decoder, compiler toolchain fingerprinter, and checksum validator.
//!
//! Provides zero-dependency extraction and parsing of the undocumented Microsoft Rich header
//! inserted between the DOS stub and PE NT headers. Reconstructs tool identifiers (`@comp.id`),
//! build numbers, and invocation counts, verifies authentic 32-bit `ROL` checksums, and computes
//! standard clear data hashes (MD5 / SHA-256) for threat intelligence pivoting.

pub mod database;
pub mod parser;
pub mod synthetic;
pub mod types;

pub use database::{determine_primary_toolchain, lookup_tool, resolve_vs_version};
pub use parser::{calculate_rich_checksum, parse_rich_bytes, parse_rich_file};
pub use synthetic::{build_synthetic_rich_pe, SyntheticRichEntry};
pub use types::{RichChecksum, RichHashes, RichRecord, RichReport, RichToolKind};
