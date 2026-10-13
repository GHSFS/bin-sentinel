// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

/// Pure-Rust RFC 3174 standard SHA-1 message digest implementation.
/// Used for legacy Windows Authenticode binary verification without external dependencies.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Creates a new SHA-1 hasher initialized with the standard initial vector.
    pub fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            count: 0,
            buffer: [0u8; 64],
            buffer_len: 0,
        }
    }

    /// Feeds input data into the cryptographic hash state.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            if self.buffer_len == 0 && (data.len() - offset) >= 64 {
                let chunk: &[u8; 64] = data[offset..offset + 64]
                    .try_into()
                    .expect("chunk slice must be 64 bytes");
                self.process_block(chunk);
                self.count = self.count.wrapping_add(64);
                offset += 64;
            } else {
                let to_copy = (64 - self.buffer_len).min(data.len() - offset);
                self.buffer[self.buffer_len..self.buffer_len + to_copy]
                    .copy_from_slice(&data[offset..offset + to_copy]);
                self.buffer_len += to_copy;
                self.count = self.count.wrapping_add(to_copy as u64);
                offset += to_copy;

                if self.buffer_len == 64 {
                    let block = self.buffer;
                    self.process_block(&block);
                    self.buffer_len = 0;
                }
            }
        }
    }

    /// Completes the hash calculation and returns the 20-byte digest.
    pub fn finalize(mut self) -> [u8; 20] {
        let total_bits = self.count.wrapping_mul(8);

        // Append 0x80 byte
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough room for 8-byte bit counter, pad with zeros and process block
        if self.buffer_len > 56 {
            for b in &mut self.buffer[self.buffer_len..64] {
                *b = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }

        // Pad with zeros up to 56 bytes
        for b in &mut self.buffer[self.buffer_len..56] {
            *b = 0;
        }

        // Append 64-bit big-endian bit length
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Convenience helper calculating a 20-byte SHA-1 digest from a byte slice.
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Convenience helper returning the lowercase hexadecimal SHA-1 string.
    pub fn digest_hex(data: &[u8]) -> String {
        hex::encode(Self::digest(data))
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (i, item) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*item);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3174_vectors() {
        assert_eq!(
            Sha1::digest_hex(b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            Sha1::digest_hex(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            Sha1::digest_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }
}
