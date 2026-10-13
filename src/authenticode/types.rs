// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::Serialize;

use crate::pe::DataDirectory;

/// Windows Certificate revision identifiers in `WIN_CERTIFICATE.wRevision`.
pub const WIN_CERT_REVISION_1_0: u16 = 0x0100;
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// Windows Certificate type identifiers in `WIN_CERTIFICATE.wCertificateType`.
pub const WIN_CERT_TYPE_X509: u16 = 0x0001;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
pub const WIN_CERT_TYPE_RESERVED_1: u16 = 0x0003;
pub const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 0x0004;

/// Recognized WIN_CERTIFICATE revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WinCertRevision {
    Revision1_0,
    Revision2_0,
    Unknown(u16),
}

impl From<u16> for WinCertRevision {
    fn from(val: u16) -> Self {
        match val {
            WIN_CERT_REVISION_1_0 => Self::Revision1_0,
            WIN_CERT_REVISION_2_0 => Self::Revision2_0,
            other => Self::Unknown(other),
        }
    }
}

impl WinCertRevision {
    pub fn display_name(&self) -> String {
        match self {
            Self::Revision1_0 => "WIN_CERT_REVISION_1_0 (0x0100)".to_string(),
            Self::Revision2_0 => "WIN_CERT_REVISION_2_0 (0x0200)".to_string(),
            Self::Unknown(v) => format!("Unknown Revision (0x{v:04X})"),
        }
    }
}

/// Recognized WIN_CERTIFICATE container types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WinCertType {
    X509,
    PkcsSignedData,
    Reserved1,
    TsStackSigned,
    Unknown(u16),
}

impl From<u16> for WinCertType {
    fn from(val: u16) -> Self {
        match val {
            WIN_CERT_TYPE_X509 => Self::X509,
            WIN_CERT_TYPE_PKCS_SIGNED_DATA => Self::PkcsSignedData,
            WIN_CERT_TYPE_RESERVED_1 => Self::Reserved1,
            WIN_CERT_TYPE_TS_STACK_SIGNED => Self::TsStackSigned,
            other => Self::Unknown(other),
        }
    }
}

impl WinCertType {
    pub fn display_name(&self) -> String {
        match self {
            Self::X509 => "X.509 Certificate (0x0001)".to_string(),
            Self::PkcsSignedData => "PKCS#7 SignedData (0x0002)".to_string(),
            Self::Reserved1 => "Reserved1 (0x0003)".to_string(),
            Self::TsStackSigned => "Terminal Server Stack Signed (0x0004)".to_string(),
            Self::Unknown(v) => format!("Unknown Certificate Type (0x{v:04X})"),
        }
    }
}

/// Individual parsed certificate entry from the PE Security Directory table.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateEntry {
    pub index: usize,
    pub file_offset: usize,
    pub length: u32,
    pub revision: u16,
    pub revision_name: String,
    pub certificate_type: u16,
    pub certificate_type_name: String,
    pub data_size: usize,
    pub digest_algorithm: Option<String>,
    pub digest_hex: Option<String>,
    pub has_timestamp: bool,
    pub program_name: Option<String>,
    pub signer_info_count: usize,
    pub is_valid_format: bool,
    pub parse_error: Option<String>,
}

/// Appended EOF overlay metadata and classification.
#[derive(Debug, Clone, Serialize)]
pub struct OverlayInfo {
    pub detected: bool,
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
    pub ratio_percent: f64,
    pub classification: String,
}

/// Computed vs embedded digest comparison for an individual cryptographic hash algorithm.
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticodeDigestInfo {
    pub algorithm: String,
    pub calculated_hex: String,
    pub embedded_hex: Option<String>,
    pub verified: Option<bool>,
}

/// Comprehensive forensic report for PE Authenticode signatures and overlays.
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticodeReport {
    pub file_path: String,
    pub file_size: usize,
    pub is_pe: bool,
    pub pe_format: Option<String>,
    pub security_directory: Option<DataDirectory>,
    pub certificates: Vec<CertificateEntry>,
    pub is_signed: bool,
    pub signature_verified: bool,
    pub digests: Vec<AuthenticodeDigestInfo>,
    pub overlay: OverlayInfo,
    pub expected_image_size: usize,
    pub alerts: Vec<String>,
}
