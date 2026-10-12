// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fmt;

/// Unified error type for binary parsing, statistical analysis, and byte patching.
#[derive(Debug)]
pub enum SentinelError {
    /// Underlying filesystem or stream I/O error.
    Io(std::io::Error),
    /// Binary header magic or structural invariant violation.
    InvalidFormat(String),
    /// Out-of-bounds offset or truncated binary slice.
    BoundsError(String),
    /// Expected bytes at patch target offset did not match actual file bytes.
    PatchMismatch {
        offset: usize,
        expected_hex: String,
        actual_hex: String,
    },
    /// Invalid user CLI parameter or hexadecimal argument.
    InvalidArgument(String),
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidFormat(msg) => write!(f, "Invalid binary format: {msg}"),
            Self::BoundsError(msg) => write!(f, "Bounds check error: {msg}"),
            Self::PatchMismatch {
                offset,
                expected_hex,
                actual_hex,
            } => write!(
                f,
                "Patch verification mismatch at offset 0x{offset:X}: expected {expected_hex}, found {actual_hex}"
            ),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
        }
    }
}

impl std::error::Error for SentinelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SentinelError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Convenience result alias for `bin-sentinel` operations.
pub type Result<T> = std::result::Result<T, SentinelError>;
