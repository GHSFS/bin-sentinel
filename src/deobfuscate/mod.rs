// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! Binary deobfuscation scanner and key recovery engine.
//!
//! Provides single-byte and multi-byte XOR, ADD, and ROL deobfuscation
//! with automated payload classification and PE/ELF/Mach-O section mapping.

pub mod decoder;
pub mod scanner;
pub mod types;

pub use decoder::*;
pub use scanner::*;
pub use types::*;
