// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::types::FuzzyDigest;

pub const ROLLING_WINDOW: usize = 7;
pub const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const FNV_PRIME: u32 = 0x01000193;
pub const FNV_INIT: u32 = 0x811c9dc5;
pub const SPAMSUM_LENGTH: usize = 64;
pub const MIN_BLOCKSIZE: u64 = 3;

/// Rolling hash state maintaining a 7-byte sliding window.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RollingHash {
    h1: u32,
    h2: u32,
    h3: u32,
    window: [u8; ROLLING_WINDOW],
    n: usize,
}

impl Default for RollingHash {
    fn default() -> Self {
        Self::new()
    }
}

impl RollingHash {
    /// Creates an initialized rolling hash state.
    pub fn new() -> Self {
        Self {
            h1: 0,
            h2: 0,
            h3: 0,
            window: [0u8; ROLLING_WINDOW],
            n: 0,
        }
    }

    /// Rolls in a single byte, updating the rolling checksum in O(1) time.
    #[inline]
    pub fn roll(&mut self, b: u8) {
        let b_u32 = b as u32;
        let old = self.window[self.n % ROLLING_WINDOW] as u32;
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add(7 * b_u32);
        self.h1 = self.h1.wrapping_add(b_u32).wrapping_sub(old);
        self.window[self.n % ROLLING_WINDOW] = b;
        self.n = self.n.wrapping_add(1);
        self.h3 = (self.h3 << 5) ^ b_u32;
    }

    /// Computes the composite rolling hash value.
    #[inline]
    pub fn value(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// Chooses the optimal starting block size for Context Triggered Piecewise Hashing.
pub fn select_block_size(length: usize) -> u64 {
    let mut b = MIN_BLOCKSIZE;
    while b.saturating_mul(SPAMSUM_LENGTH as u64) < (length as u64) {
        b = b.saturating_mul(2);
    }
    b
}

/// Appends a base64 character to a digest string while suppressing identical runs over 3 chars.
fn push_digest_char(s: &mut String, c: char) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len >= 3
        && bytes[len - 1] as char == c
        && bytes[len - 2] as char == c
        && bytes[len - 3] as char == c
    {
        return;
    }
    s.push(c);
}

/// Computes a piecewise fuzzy hash (CTPH / SSDEEP-style) for a raw byte slice.
pub fn compute_fuzzy_digest(data: &[u8]) -> FuzzyDigest {
    if data.is_empty() {
        return FuzzyDigest::new(MIN_BLOCKSIZE, String::new(), String::new());
    }

    let b1 = select_block_size(data.len());
    let b2 = b1.saturating_mul(2);

    let (hash1, hash2) = generate_dual_block_hashes(data, b1, b2);
    FuzzyDigest::new(b1, hash1, hash2)
}

/// Generates dual block hashes for primary block size `b1` and secondary block size `b2`.
pub fn generate_dual_block_hashes(data: &[u8], b1: u64, b2: u64) -> (String, String) {
    let mut rolling = RollingHash::new();
    let mut block_hash1: u32 = FNV_INIT;
    let mut block_hash2: u32 = FNV_INIT;

    let mut hash1 = String::with_capacity(SPAMSUM_LENGTH);
    let mut hash2 = String::with_capacity(SPAMSUM_LENGTH);

    let b1_trigger = (b1 as u32).saturating_sub(1);
    let b2_trigger = (b2 as u32).saturating_sub(1);

    for &byte in data {
        rolling.roll(byte);

        // Mix into block accumulators (FNV-1a)
        block_hash1 = (block_hash1 ^ (byte as u32)).wrapping_mul(FNV_PRIME);
        block_hash2 = (block_hash2 ^ (byte as u32)).wrapping_mul(FNV_PRIME);

        // Trigger boundary check for block size 1
        if (rolling.value() % (b1 as u32)) == b1_trigger && hash1.len() < SPAMSUM_LENGTH {
            let idx = (block_hash1 % 64) as usize;
            push_digest_char(&mut hash1, BASE64_ALPHABET[idx] as char);
            block_hash1 = FNV_INIT;
        }

        // Trigger boundary check for block size 2
        if (rolling.value() % (b2 as u32)) == b2_trigger && hash2.len() < (SPAMSUM_LENGTH / 2) {
            let idx = (block_hash2 % 64) as usize;
            push_digest_char(&mut hash2, BASE64_ALPHABET[idx] as char);
            block_hash2 = FNV_INIT;
        }
    }

    // Flush any pending trailing bytes
    if (block_hash1 != FNV_INIT || hash1.is_empty()) && hash1.len() < SPAMSUM_LENGTH {
        let idx = (block_hash1 % 64) as usize;
        push_digest_char(&mut hash1, BASE64_ALPHABET[idx] as char);
    }

    if (block_hash2 != FNV_INIT || hash2.is_empty()) && hash2.len() < SPAMSUM_LENGTH {
        let idx = (block_hash2 % 64) as usize;
        push_digest_char(&mut hash2, BASE64_ALPHABET[idx] as char);
    }

    // Zeroize sensitive accumulators
    block_hash1.zeroize();
    block_hash2.zeroize();

    (hash1, hash2)
}
