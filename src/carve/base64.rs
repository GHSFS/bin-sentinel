// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::CarveEncodingKind;

/// Internal candidate representation before classification.
#[derive(Debug, Clone)]
pub struct RawCarvedCandidate {
    pub file_offset: usize,
    pub encoded_length: usize,
    pub encoding: CarveEncodingKind,
    pub decoded_bytes: Vec<u8>,
}

/// Decodes an RFC 4648 Base64 slice (Standard or URL-Safe).
pub fn decode_base64(input: &[u8], is_url_safe: bool) -> Option<Vec<u8>> {
    let mut clean_chars = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        clean_chars.push(b);
    }

    if clean_chars.len() < 4 || clean_chars.len() % 4 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity((clean_chars.len() / 4) * 3);
    let mut i = 0;
    while i < clean_chars.len() {
        let b0 = clean_chars[i];
        let b1 = clean_chars[i + 1];
        let b2 = clean_chars[i + 2];
        let b3 = clean_chars[i + 3];

        let v0 = b64_val(b0, is_url_safe)?;
        let v1 = b64_val(b1, is_url_safe)?;

        output.push((v0 << 2) | (v1 >> 4));

        if b2 == b'=' {
            if b3 != b'=' || i + 4 != clean_chars.len() {
                return None;
            }
            break;
        }
        let v2 = b64_val(b2, is_url_safe)?;
        output.push(((v1 & 0x0F) << 4) | (v2 >> 2));

        if b3 == b'=' {
            if i + 4 != clean_chars.len() {
                return None;
            }
            break;
        }
        let v3 = b64_val(b3, is_url_safe)?;
        output.push(((v2 & 0x03) << 6) | v3);

        i += 4;
    }

    // Filter out degenerate all-zero or non-informative buffers
    if output.is_empty() || output.iter().all(|&b| b == 0) {
        return None;
    }

    Some(output)
}

#[inline]
fn b64_val(c: u8, is_url_safe: bool) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' if !is_url_safe => Some(62),
        b'/' if !is_url_safe => Some(63),
        b'-' if is_url_safe => Some(62),
        b'_' if is_url_safe => Some(63),
        _ => None,
    }
}

#[inline]
fn is_b64_char(c: u8, url_safe: bool) -> bool {
    c.is_ascii_alphanumeric()
        || (!url_safe && (c == b'+' || c == b'/'))
        || (url_safe && (c == b'-' || c == b'_'))
        || c == b'='
}

/// Scans raw byte buffers for embedded Base64 sequences (ASCII and UTF-16LE).
pub fn scan_base64_candidates(
    data: &[u8],
    min_length: usize,
    max_candidates: usize,
) -> Vec<RawCarvedCandidate> {
    let mut results = Vec::new();
    let min_len = min_length.max(16);

    // 1. ASCII Base64 scanning
    let mut i = 0;
    while i < data.len() && results.len() < max_candidates {
        if is_b64_char(data[i], false) || is_b64_char(data[i], true) {
            let start = i;
            let mut has_url_chars = false;
            let mut has_std_chars = false;

            while i < data.len() && is_b64_char(data[i], false)
                || (i < data.len() && is_b64_char(data[i], true))
            {
                if data[i] == b'-' || data[i] == b'_' {
                    has_url_chars = true;
                } else if data[i] == b'+' || data[i] == b'/' {
                    has_std_chars = true;
                }
                i += 1;
            }

            let len = i - start;
            if len >= min_len {
                let candidate_slice = &data[start..i];
                let (url_safe, kind) = if has_url_chars && !has_std_chars {
                    (true, CarveEncodingKind::UrlSafeBase64)
                } else {
                    (false, CarveEncodingKind::StandardBase64)
                };

                // Normalize length to multiple of 4
                let valid_len = (len / 4) * 4;
                if valid_len >= min_len {
                    if let Some(decoded) = decode_base64(&candidate_slice[..valid_len], url_safe) {
                        results.push(RawCarvedCandidate {
                            file_offset: start,
                            encoded_length: valid_len,
                            encoding: kind,
                            decoded_bytes: decoded,
                        });
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    // 2. UTF-16LE Base64 scanning (e.g. PowerShell scripts with wide string encoded commands)
    let mut j = 0;
    while j + 1 < data.len() && results.len() < max_candidates {
        if data[j + 1] == 0 && (is_b64_char(data[j], false) || is_b64_char(data[j], true)) {
            let start = j;
            let mut ascii_bytes = Vec::new();
            let mut has_url_chars = false;
            let mut has_std_chars = false;

            while j + 1 < data.len()
                && data[j + 1] == 0
                && (is_b64_char(data[j], false) || is_b64_char(data[j], true))
            {
                let c = data[j];
                if c == b'-' || c == b'_' {
                    has_url_chars = true;
                } else if c == b'+' || c == b'/' {
                    has_std_chars = true;
                }
                ascii_bytes.push(c);
                j += 2;
            }

            if ascii_bytes.len() >= min_len {
                let (url_safe, kind) = if has_url_chars && !has_std_chars {
                    (true, CarveEncodingKind::UrlSafeBase64)
                } else {
                    (false, CarveEncodingKind::StandardBase64)
                };
                let valid_len = (ascii_bytes.len() / 4) * 4;
                if valid_len >= min_len {
                    if let Some(decoded) = decode_base64(&ascii_bytes[..valid_len], url_safe) {
                        results.push(RawCarvedCandidate {
                            file_offset: start,
                            encoded_length: valid_len * 2, // 2 bytes per UTF-16 char
                            encoding: kind,
                            decoded_bytes: decoded,
                        });
                    }
                }
            }
        } else {
            j += 1;
        }
    }

    results
}
