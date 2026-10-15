// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::base64::RawCarvedCandidate;
use super::types::CarveEncodingKind;

#[inline]
fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Scans raw byte buffers for embedded Hex-encoded sequences.
pub fn scan_hex_candidates(
    data: &[u8],
    min_length: usize,
    max_candidates: usize,
) -> Vec<RawCarvedCandidate> {
    let mut results = Vec::new();
    let min_len = min_length.max(16);

    // 1. Scan Formatted Hex: `\x4d\x5a\x90...`
    let mut i = 0;
    while i + 3 < data.len() && results.len() < max_candidates {
        if data[i] == b'\\' && (data[i + 1] == b'x' || data[i + 1] == b'X') {
            let start = i;
            let mut decoded = Vec::new();
            let mut curr = i;

            while curr + 3 < data.len()
                && data[curr] == b'\\'
                && (data[curr + 1] == b'x' || data[curr + 1] == b'X')
            {
                if let (Some(h), Some(l)) = (
                    from_hex_digit(data[curr + 2]),
                    from_hex_digit(data[curr + 3]),
                ) {
                    decoded.push((h << 4) | l);
                    curr += 4;
                } else {
                    break;
                }
            }

            let encoded_len = curr - start;
            if encoded_len >= min_len && decoded.len() >= 8 && !decoded.iter().all(|&b| b == 0) {
                results.push(RawCarvedCandidate {
                    file_offset: start,
                    encoded_length: encoded_len,
                    encoding: CarveEncodingKind::FormattedHex,
                    decoded_bytes: decoded,
                });
            }
            i = curr.max(i + 1);
        } else {
            i += 1;
        }
    }

    // 2. Scan Formatted Hex: `0x4d, 0x5a, 0x90...` or `0x4d 0x5a`
    i = 0;
    while i + 3 < data.len() && results.len() < max_candidates {
        if data[i] == b'0' && (data[i + 1] == b'x' || data[i + 1] == b'X') {
            let start = i;
            let mut decoded = Vec::new();
            let mut curr = i;

            while curr + 3 < data.len()
                && data[curr] == b'0'
                && (data[curr + 1] == b'x' || data[curr + 1] == b'X')
            {
                if let (Some(h), Some(l)) = (
                    from_hex_digit(data[curr + 2]),
                    from_hex_digit(data[curr + 3]),
                ) {
                    decoded.push((h << 4) | l);
                    curr += 4;
                    // skip optional separators: comma, space, semicolon
                    while curr < data.len()
                        && (data[curr] == b','
                            || data[curr] == b' '
                            || data[curr] == b'\t'
                            || data[curr] == b';')
                    {
                        curr += 1;
                    }
                } else {
                    break;
                }
            }

            let encoded_len = curr - start;
            if encoded_len >= min_len && decoded.len() >= 8 && !decoded.iter().all(|&b| b == 0) {
                results.push(RawCarvedCandidate {
                    file_offset: start,
                    encoded_length: encoded_len,
                    encoding: CarveEncodingKind::FormattedHex,
                    decoded_bytes: decoded,
                });
            }
            i = curr.max(i + 1);
        } else {
            i += 1;
        }
    }

    // 3. Scan Space-Separated Hex Pairs: `4D 5A 90 00 ...`
    i = 0;
    while i + 2 < data.len() && results.len() < max_candidates {
        if from_hex_digit(data[i]).is_some()
            && from_hex_digit(data[i + 1]).is_some()
            && (data[i + 2] == b' ' || data[i + 2] == b'-' || data[i + 2] == b':')
        {
            let start = i;
            let sep = data[i + 2];
            let mut decoded = Vec::new();
            let mut curr = i;

            while curr + 1 < data.len() {
                if let (Some(h), Some(l)) =
                    (from_hex_digit(data[curr]), from_hex_digit(data[curr + 1]))
                {
                    decoded.push((h << 4) | l);
                    curr += 2;
                    if curr < data.len() && data[curr] == sep {
                        curr += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            let encoded_len = curr - start;
            if encoded_len >= min_len && decoded.len() >= 8 && !decoded.iter().all(|&b| b == 0) {
                results.push(RawCarvedCandidate {
                    file_offset: start,
                    encoded_length: encoded_len,
                    encoding: CarveEncodingKind::FormattedHex,
                    decoded_bytes: decoded,
                });
            }
            i = curr.max(i + 1);
        } else {
            i += 1;
        }
    }

    // 4. Scan Contiguous Hex Strings: `4D5A90000300000004000000FFFF0000...`
    i = 0;
    while i < data.len() && results.len() < max_candidates {
        if from_hex_digit(data[i]).is_some() {
            let start = i;
            let mut has_hex_letters = false;

            while i < data.len() && from_hex_digit(data[i]).is_some() {
                let c = data[i];
                if (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c) {
                    has_hex_letters = true;
                }
                i += 1;
            }

            let hex_len = i - start;
            // Require even length, minimum 24 chars (12 bytes), and at least some hex letters
            // to avoid false positive triggers on plain decimal numbers like timestamps or phone numbers.
            if hex_len >= 24 && has_hex_letters {
                let even_len = (hex_len / 2) * 2;
                let mut decoded = Vec::with_capacity(even_len / 2);
                let mut k = start;
                while k < start + even_len {
                    if let (Some(h), Some(l)) =
                        (from_hex_digit(data[k]), from_hex_digit(data[k + 1]))
                    {
                        decoded.push((h << 4) | l);
                    }
                    k += 2;
                }

                if decoded.len() >= 12 && !decoded.iter().all(|&b| b == 0) {
                    results.push(RawCarvedCandidate {
                        file_offset: start,
                        encoded_length: even_len,
                        encoding: CarveEncodingKind::ContiguousHex,
                        decoded_bytes: decoded,
                    });
                }
            }
        } else {
            i += 1;
        }
    }

    results
}
