// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod headers;
pub mod parser;
pub mod synthetic;

pub use headers::*;
pub use parser::{parse_macho, parse_single_macho_64};
pub use synthetic::{build_synthetic_macho64, build_synthetic_macho_universal};
