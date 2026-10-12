// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::Serialize;

use crate::pe::{PeInfo, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};

/// Distribution of byte classes across a binary buffer.
#[derive(Debug, Clone, Serialize)]
pub struct ByteClassification {
    pub total_bytes: usize,
    pub null_ratio: f64,
    pub ascii_printable_ratio: f64,
    pub high_byte_ratio: f64,
}

/// Sliding-window entropy sample entry.
#[derive(Debug, Clone, Serialize)]
pub struct EntropyWindow {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
}

/// Complete statistical entropy report for a binary file.
#[derive(Debug, Clone, Serialize)]
pub struct EntropyReport {
    pub overall_entropy: f64,
    pub chi_square: f64,
    pub assessment: String,
    pub classification: ByteClassification,
    pub windows: Vec<EntropyWindow>,
}

/// Computes Shannon entropy ($0.0..=8.0$ bits per byte) over a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes Pearson's Chi-Square ($\chi^2$) uniformity statistic against a uniform 256-value distribution.
pub fn chi_square_uniformity(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = (data.len() as f64) / 256.0;
    let mut chi_sq = 0.0;
    for &c in &counts {
        let diff = (c as f64) - expected;
        chi_sq += (diff * diff) / expected;
    }
    (chi_sq * 100.0).round() / 100.0
}

/// Classifies bytes into null (`0x00`), printable ASCII (`0x20..=0x7E` plus whitespace), and high bytes (`>= 0x80`).
pub fn byte_classification(data: &[u8]) -> ByteClassification {
    if data.is_empty() {
        return ByteClassification {
            total_bytes: 0,
            null_ratio: 0.0,
            ascii_printable_ratio: 0.0,
            high_byte_ratio: 0.0,
        };
    }

    let mut nulls = 0usize;
    let mut ascii = 0usize;
    let mut high = 0usize;

    for &b in data {
        if b == 0 {
            nulls += 1;
        } else if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            ascii += 1;
        } else if b >= 0x80 {
            high += 1;
        }
    }

    let len = data.len() as f64;
    ByteClassification {
        total_bytes: data.len(),
        null_ratio: ((nulls as f64 / len) * 10000.0).round() / 10000.0,
        ascii_printable_ratio: ((ascii as f64 / len) * 10000.0).round() / 10000.0,
        high_byte_ratio: ((high as f64 / len) * 10000.0).round() / 10000.0,
    }
}

/// Evaluates sliding-window entropy and overall byte statistics across `data`.
pub fn analyze_entropy_windows(data: &[u8], window_size: usize) -> EntropyReport {
    let effective_window = window_size.max(64);
    let overall = (shannon_entropy(data) * 10000.0).round() / 10000.0;
    let chi_sq = chi_square_uniformity(data);
    let classification = byte_classification(data);

    let assessment = if overall >= 7.2 {
        "High entropy (likely packed, compressed, or encrypted payload)".to_string()
    } else if overall >= 5.5 {
        "Moderate entropy (standard compiled native machine code)".to_string()
    } else {
        "Low entropy (structured headers, text strings, or zero-padded data)".to_string()
    };

    let mut windows = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + effective_window).min(data.len());
        let slice = &data[offset..end];
        let ent = (shannon_entropy(slice) * 10000.0).round() / 10000.0;
        windows.push(EntropyWindow {
            offset,
            length: slice.len(),
            entropy: ent,
        });
        offset = end;
    }

    EntropyReport {
        overall_entropy: overall,
        chi_square: chi_sq,
        assessment,
        classification,
        windows,
    }
}

/// Inspects parsed PE sections and raw binary bytes for known packer signatures and structural anomalies.
pub fn detect_packer_signatures(pe: &PeInfo, raw: &[u8]) -> Vec<String> {
    let mut alerts = Vec::new();

    for sec in &pe.sections {
        let upper = sec.name.to_ascii_uppercase();
        if upper.starts_with("UPX") {
            alerts.push(format!(
                "Packer signature detected: UPX section '{}'",
                sec.name
            ));
        } else if upper.starts_with(".VMP") {
            alerts.push(format!(
                "Packer/virtualizer signature detected: VMProtect section '{}'",
                sec.name
            ));
        } else if upper.starts_with(".THEMIDA") || upper.starts_with(".WINLIC") {
            alerts.push(format!(
                "Packer signature detected: Themida/WinLicense section '{}'",
                sec.name
            ));
        } else if upper.starts_with(".ASPACK") || upper.starts_with(".MPress") {
            alerts.push(format!("Packer signature detected: section '{}'", sec.name));
        }

        if sec.rwx_anomaly {
            alerts.push(format!(
                "RWX memory permission anomaly in section '{}' (writable + executable)",
                sec.name
            ));
        }

        let is_code_or_exec = (sec.characteristics & IMAGE_SCN_CNT_CODE) != 0
            || (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if sec.entropy >= 7.2 && (is_code_or_exec || sec.raw_size >= 256) {
            alerts.push(format!(
                "High-entropy section '{}' ({:.4} bits/byte >= 7.2000 threshold)",
                sec.name, sec.entropy
            ));
        }
    }

    // Raw marker scan for UPX! magic
    if raw.windows(4).any(|w| w == b"UPX!") && !alerts.iter().any(|a| a.contains("UPX")) {
        alerts.push("Packer marker 'UPX!' found in binary stream".to_string());
    }

    if !pe.mitigations.aslr {
        alerts.push(
            "Missing exploit mitigation: ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)".into(),
        );
    }
    if !pe.mitigations.dep_nx {
        alerts
            .push("Missing exploit mitigation: DEP/NX (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)".into());
    }

    alerts
}
