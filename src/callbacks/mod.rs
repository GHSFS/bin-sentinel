// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod synthetic;
pub mod tls;
pub mod types;
pub mod unwind;

pub use synthetic::{build_synthetic_callbacks_pe, SyntheticCallbacksSpec, SyntheticPdataSpec};
pub use tls::parse_tls_directory;
pub use types::*;
pub use unwind::{
    parse_exception_directory, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_NHANDLER,
    UNW_FLAG_UHANDLER,
};

use crate::error::Result;
use crate::pe::parse_pe;
use std::fs;
use std::path::Path;

/// Inspects in-memory PE byte buffer for TLS callbacks and x64 exception unwind tables.
pub fn inspect_callbacks_bytes(data: &[u8], file_path: &str) -> Result<CallbacksReport> {
    let pe = parse_pe(data)?;
    let mut alerts = Vec::new();

    let tls = parse_tls_directory(data, &pe, &mut alerts)?;
    let exceptions = parse_exception_directory(data, &pe, &mut alerts)?;

    let mut anomaly_count = 0;
    for cb in &tls.callbacks {
        if cb.anomaly.is_some() {
            anomaly_count += 1;
        }
    }
    for func in &exceptions.functions {
        if func.anomaly.is_some() {
            anomaly_count += 1;
        }
        if let Some(ref u) = func.unwind_info {
            if u.has_handler && (!u.handler_executable || u.handler_writable) {
                anomaly_count += 1;
            }
        }
    }

    let summary = CallbacksSummary {
        tls_callback_count: tls.callbacks.len(),
        pdata_function_count: exceptions.total_functions,
        pdata_handler_count: exceptions.functions_with_handlers,
        has_pre_main_execution: !tls.callbacks.is_empty(),
        anomalies_detected: anomaly_count,
    };

    Ok(CallbacksReport {
        file_path: file_path.to_string(),
        format: pe.format,
        image_base: pe.image_base,
        entry_point_rva: pe.entry_point,
        tls,
        exceptions,
        summary,
        alerts,
    })
}

/// Inspects a PE file on disk for TLS callbacks and x64 exception unwind tables.
pub fn inspect_callbacks_file<P: AsRef<Path>>(path: P) -> Result<CallbacksReport> {
    let p = path.as_ref();
    let data = fs::read(p)?;
    inspect_callbacks_bytes(&data, &p.display().to_string())
}
