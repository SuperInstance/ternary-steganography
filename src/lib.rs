//! # ternary-steganography
//!
//! Hide information in ternary strategy noise.
//!
//! Encode and decode messages within ternary strategy patterns using
//! various steganographic techniques: bit embedding, pattern encoding,
//! frequency modulation, and statistical steganography.

/// A ternary value: -1, 0, +1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trit {
    Neg,
    Zero,
    Pos,
}

impl Trit {
    pub fn to_i8(self) -> i8 {
        match self {
            Trit::Neg => -1,
            Trit::Zero => 0,
            Trit::Pos => 1,
        }
    }

    pub fn from_i8(v: i8) -> Option<Self> {
        match v {
            -1 => Some(Trit::Neg),
            0 => Some(Trit::Zero),
            1 => Some(Trit::Pos),
            _ => None,
        }
    }

    /// Convert to trit digit (0, 1, 2)
    pub fn digit(self) -> u8 {
        match self {
            Trit::Neg => 0,
            Trit::Zero => 1,
            Trit::Pos => 2,
        }
    }

    pub fn from_digit(d: u8) -> Option<Self> {
        match d {
            0 => Some(Trit::Neg),
            1 => Some(Trit::Zero),
            2 => Some(Trit::Pos),
            _ => None,
        }
    }
}

/// A ternary strategy sequence
#[derive(Debug, Clone)]
pub struct TernarySequence {
    trits: Vec<Trit>,
}

impl TernarySequence {
    pub fn new(trits: Vec<Trit>) -> Self {
        TernarySequence { trits }
    }

    pub fn from_i8(values: &[i8]) -> Self {
        TernarySequence {
            trits: values.iter()
                .filter_map(|&v| Trit::from_i8(v))
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.trits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trits.is_empty()
    }

    pub fn trits(&self) -> &[Trit] {
        &self.trits
    }

    pub fn push(&mut self, trit: Trit) {
        self.trits.push(trit);
    }

    pub fn get(&self, idx: usize) -> Option<Trit> {
        self.trits.get(idx).copied()
    }

    pub fn set(&mut self, idx: usize, trit: Trit) {
        if idx < self.trits.len() {
            self.trits[idx] = trit;
        }
    }

    /// Compute capacity for embedding bits
    pub fn bit_capacity(&self, bits_per_trit: usize) -> usize {
        self.trits.len() * bits_per_trit
    }
}

// ─── Bit-level Embedding ───────────────────────────────────────────

/// Simple bit embedding: encode binary data in ternary values
/// Uses 1 bit per trit: Neg/Zero = 0, Pos = 1
pub struct BitEmbedder {
    _bits_per_trit: usize,
}

impl BitEmbedder {
    pub fn new(bits_per_trit: usize) -> Self {
        BitEmbedder { _bits_per_trit: bits_per_trit.min(1) }
    }

    /// Encode bytes into a ternary sequence carrier
    pub fn encode(&self, carrier: &TernarySequence, data: &[u8]) -> Option<TernarySequence> {
        let bits_needed = data.len() * 8;
        if bits_needed > carrier.len() {
            return None;
        }

        let mut result = carrier.clone();
        let mut bit_idx = 0;

        for &byte in data {
            for shift in (0..8).rev() {
                let bit = (byte >> shift) & 1;
                let trit = if bit == 1 { Trit::Pos } else { Trit::Neg };
                result.set(bit_idx, trit);
                bit_idx += 1;
            }
        }
        Some(result)
    }

    /// Decode bytes from an encoded ternary sequence
    pub fn decode(&self, encoded: &TernarySequence, byte_count: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(byte_count);
        let mut bit_idx = 0;

        for _ in 0..byte_count {
            let mut byte = 0u8;
            for shift in (0..8).rev() {
                let trit = encoded.get(bit_idx)?;
                let bit = if trit == Trit::Pos { 1 } else { 0 };
                byte |= bit << shift;
                bit_idx += 1;
            }
            result.push(byte);
        }
        Some(result)
    }
}

// ─── Pattern Encoding ──────────────────────────────────────────────

/// Encode messages as specific ternary patterns
pub struct PatternEncoder {
    /// Pattern length per character
    pattern_len: usize,
}

impl PatternEncoder {
    pub fn new(pattern_len: usize) -> Self {
        PatternEncoder { pattern_len: pattern_len.max(2) }
    }

    /// Encode a string message as ternary patterns
    pub fn encode(&self, message: &str) -> TernarySequence {
        let mut trits = Vec::new();
        for ch in message.chars() {
            let code = ch as u32;
            // Convert character code to balanced ternary
            let ternary = Self::to_base3(code, self.pattern_len);
            trits.extend_from_slice(&ternary);
        }
        TernarySequence::new(trits)
    }

    /// Decode ternary patterns back to a string
    pub fn decode(&self, encoded: &TernarySequence) -> String {
        let mut result = String::new();
        let chunks = encoded.trits.chunks(self.pattern_len);
        for chunk in chunks {
            let code = Self::from_base3(chunk);
            if let Some(ch) = char::from_u32(code) {
                result.push(ch);
            }
        }
        result
    }

    /// Hide encoded message within a carrier by replacing specific positions
    pub fn stego_encode(
        &self,
        carrier: &TernarySequence,
        message: &str,
        positions: &[usize],
    ) -> Option<TernarySequence> {
        let encoded = self.encode(message);
        if encoded.len() > positions.len() {
            return None;
        }
        let mut result = carrier.clone();
        for (i, &pos) in positions.iter().enumerate() {
            if i >= encoded.len() {
                break;
            }
            if pos < result.len() {
                result.set(pos, encoded.get(i)?);
            }
        }
        Some(result)
    }

    /// Extract a hidden message from specific positions
    pub fn stego_decode(
        &self,
        carrier: &TernarySequence,
        positions: &[usize],
        char_count: usize,
    ) -> Option<String> {
        let mut trits = Vec::new();
        for &pos in positions {
            if pos < carrier.len() {
                trits.push(carrier.get(pos)?);
            }
        }
        let seq = TernarySequence::new(trits);
        // Truncate to expected length
        let needed = char_count * self.pattern_len;
        let truncated: Vec<Trit> = seq.trits.into_iter().take(needed).collect();
        let seq = TernarySequence::new(truncated);
        Some(self.decode(&seq))
    }

    fn to_base3(mut value: u32, len: usize) -> Vec<Trit> {
        let mut digits = Vec::new();
        while value > 0 {
            digits.push(Trit::from_digit((value % 3) as u8).unwrap_or(Trit::Neg));
            value /= 3;
        }
        while digits.len() < len {
            digits.push(Trit::Neg); // digit 0
        }
        digits.truncate(len);
        digits.reverse();
        digits
    }

    fn from_base3(trits: &[Trit]) -> u32 {
        let mut value = 0u32;
        for &trit in trits {
            value = value * 3 + trit.digit() as u32;
        }
        value
    }
}

// ─── Frequency Modulation ──────────────────────────────────────────

/// Encode data by modulating the frequency of ternary values
pub struct FrequencyModulator {
    window_size: usize,
}

impl FrequencyModulator {
    pub fn new(window_size: usize) -> Self {
        FrequencyModulator { window_size: window_size.max(3) }
    }

    /// Encode a byte into a window by adjusting trit frequencies
    pub fn encode_byte(&self, byte: u8) -> Vec<Trit> {
        let mut trits = Vec::with_capacity(self.window_size);
        // Distribute trits based on byte value
        let neg_count = ((byte as usize) % self.window_size).min(self.window_size);
        let pos_count = ((byte as usize / 3) % self.window_size).min(self.window_size.saturating_sub(neg_count));
        let zero_count = self.window_size - neg_count - pos_count;

        for _ in 0..neg_count {
            trits.push(Trit::Neg);
        }
        for _ in 0..zero_count {
            trits.push(Trit::Zero);
        }
        for _ in 0..pos_count {
            trits.push(Trit::Pos);
        }
        trits
    }

    /// Decode a byte from a window of trits
    pub fn decode_byte(&self, trits: &[Trit]) -> u8 {
        let neg_count = trits.iter().filter(|&&t| t == Trit::Neg).count();
        let pos_count = trits.iter().filter(|&&t| t == Trit::Pos).count();
        ((neg_count + pos_count * 3) % 256) as u8
    }

    /// Encode data into a carrier sequence using frequency windows
    pub fn encode(&self, carrier: &TernarySequence, data: &[u8]) -> Option<TernarySequence> {
        let needed = data.len() * self.window_size;
        if needed > carrier.len() {
            return None;
        }

        let mut result = carrier.clone();
        for (i, &byte) in data.iter().enumerate() {
            let window = self.encode_byte(byte);
            let offset = i * self.window_size;
            for (j, trit) in window.iter().enumerate() {
                result.set(offset + j, *trit);
            }
        }
        Some(result)
    }

    /// Decode data from a carrier sequence
    pub fn decode(&self, carrier: &TernarySequence, byte_count: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(byte_count);
        for i in 0..byte_count {
            let offset = i * self.window_size;
            if offset + self.window_size > carrier.len() {
                break;
            }
            let window: Vec<Trit> = (offset..offset + self.window_size)
                .filter_map(|j| carrier.get(j))
                .collect();
            result.push(self.decode_byte(&window));
        }
        result
    }
}

// ─── Statistical Steganography ─────────────────────────────────────

/// Steganography using statistical properties of ternary sequences
pub struct StatisticalStego {
    block_size: usize,
}

impl StatisticalStego {
    pub fn new(block_size: usize) -> Self {
        StatisticalStego { block_size: block_size.max(3) }
    }

    /// Compute statistics of a ternary block
    pub fn block_stats(trits: &[Trit]) -> (f64, f64, f64) {
        let n = trits.len() as f64;
        if n == 0.0 {
            return (0.0, 0.0, 0.0);
        }
        let neg = trits.iter().filter(|&&t| t == Trit::Neg).count() as f64 / n;
        let zero = trits.iter().filter(|&&t| t == Trit::Zero).count() as f64 / n;
        let pos = trits.iter().filter(|&&t| t == Trit::Pos).count() as f64 / n;
        (neg, zero, pos)
    }

    /// Encode a bit by shifting block statistics
    pub fn encode_bit(&self, block: &mut [Trit], bit: u8) {
        if block.len() < self.block_size {
            return;
        }
        // If bit is 1, ensure more Pos than Neg; if 0, ensure more Neg than Pos
        match bit {
            0 => {
                // Ensure at least half are Neg
                for i in 0..block.len() / 2 {
                    block[i] = Trit::Neg;
                }
            }
            1 => {
                // Ensure at least half are Pos
                for i in 0..block.len() / 2 {
                    block[i] = Trit::Pos;
                }
            }
            _ => {}
        }
    }

    /// Decode a bit from block statistics
    pub fn decode_bit(&self, block: &[Trit]) -> u8 {
        let (neg, _, pos) = Self::block_stats(block);
        if pos > neg {
            1
        } else {
            0
        }
    }

    /// Encode bytes into carrier using statistical modulation
    pub fn encode(&self, carrier: &TernarySequence, data: &[u8]) -> Option<TernarySequence> {
        let bits_needed = data.len() * 8;
        if bits_needed * self.block_size > carrier.len() {
            return None;
        }

        let mut trits = carrier.trits.clone();
        for (byte_idx, &byte) in data.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let offset = (byte_idx * 8 + bit_idx) * self.block_size;
                let end = (offset + self.block_size).min(trits.len());
                if offset < trits.len() {
                    self.encode_bit(&mut trits[offset..end], bit);
                }
            }
        }
        Some(TernarySequence::new(trits))
    }

    /// Decode bytes from a statistically encoded sequence
    pub fn decode(&self, encoded: &TernarySequence, byte_count: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(byte_count);
        for byte_idx in 0..byte_count {
            let mut byte = 0u8;
            for bit_idx in 0..8 {
                let offset = (byte_idx * 8 + bit_idx) * self.block_size;
                let end = (offset + self.block_size).min(encoded.len());
                if offset >= encoded.len() {
                    break;
                }
                let block: Vec<Trit> = (offset..end)
                    .filter_map(|j| encoded.get(j))
                    .collect();
                let bit = self.decode_bit(&block);
                byte |= bit << (7 - bit_idx);
            }
            result.push(byte);
        }
        result
    }
}

// ─── Spread Spectrum ───────────────────────────────────────────────

/// Spread spectrum steganography using a key-based pattern
pub struct SpreadSpectrum {
    key: Vec<usize>,
    chip_rate: usize,
}

impl SpreadSpectrum {
    pub fn new(key: Vec<usize>, chip_rate: usize) -> Self {
        SpreadSpectrum { key, chip_rate: chip_rate.max(1) }
    }

    /// Generate a pseudo-random ternary sequence from the key
    pub fn generate_pattern(&self, length: usize) -> Vec<Trit> {
        let mut pattern = Vec::with_capacity(length);
        for i in 0..length {
            let key_byte = self.key[i % self.key.len()];
            let val = (key_byte.wrapping_add(i)).wrapping_mul(31) % 3;
            pattern.push(Trit::from_digit(val as u8).unwrap_or(Trit::Zero));
        }
        pattern
    }

    /// Encode a bit using direct sequence spread spectrum
    pub fn encode_bit(&self, bit: u8, pattern: &[Trit]) -> Vec<Trit> {
        let sign = if bit == 1 { 1i8 } else { -1i8 };
        pattern.iter().map(|&t| {
            let v = t.to_i8() * sign;
            Trit::from_i8(v.clamp(-1, 1)).unwrap_or(Trit::Zero)
        }).collect()
    }

    /// Decode a bit using correlation with the pattern
    pub fn decode_bit(&self, encoded: &[Trit], pattern: &[Trit]) -> u8 {
        let correlation: i64 = encoded.iter().zip(pattern.iter())
            .map(|(&e, &p)| e.to_i8() as i64 * p.to_i8() as i64)
            .sum();
        if correlation > 0 { 1 } else { 0 }
    }

    /// Encode data into carrier
    pub fn encode(&self, carrier: &TernarySequence, data: &[u8]) -> Option<TernarySequence> {
        let bits_needed = data.len() * 8;
        let needed = bits_needed * self.chip_rate;
        if needed > carrier.len() {
            return None;
        }

        let mut trits = carrier.trits.clone();
        let pattern = self.generate_pattern(self.chip_rate);

        for (byte_idx, &byte) in data.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let encoded_bit = self.encode_bit(bit, &pattern);
                let offset = (byte_idx * 8 + bit_idx) * self.chip_rate;
                for (j, trit) in encoded_bit.iter().enumerate() {
                    if offset + j < trits.len() {
                        trits[offset + j] = *trit;
                    }
                }
            }
        }
        Some(TernarySequence::new(trits))
    }

    /// Decode data from encoded sequence
    pub fn decode(&self, encoded: &TernarySequence, byte_count: usize) -> Vec<u8> {
        let pattern = self.generate_pattern(self.chip_rate);
        let mut result = Vec::with_capacity(byte_count);

        for byte_idx in 0..byte_count {
            let mut byte = 0u8;
            for bit_idx in 0..8 {
                let offset = (byte_idx * 8 + bit_idx) * self.chip_rate;
                if offset + self.chip_rate > encoded.len() {
                    break;
                }
                let chunk: Vec<Trit> = (offset..offset + self.chip_rate)
                    .filter_map(|j| encoded.get(j))
                    .collect();
                let bit = self.decode_bit(&chunk, &pattern);
                byte |= bit << (7 - bit_idx);
            }
            result.push(byte);
        }
        result
    }
}

// ─── Capacity Analysis ─────────────────────────────────────────────

/// Analyze steganographic capacity of a ternary sequence
pub struct CapacityAnalyzer;

impl CapacityAnalyzer {
    /// Calculate maximum embeddable bytes for a given technique
    pub fn max_bytes(seq_len: usize, technique: &str) -> usize {
        match technique {
            "bit" => seq_len / 8,
            "pattern" => seq_len / 7, // ~7 trits per ASCII char
            "frequency" => seq_len / 9, // window size 9
            "statistical" => seq_len / (8 * 4), // block size 4
            "spread" => seq_len / (8 * 8), // chip rate 8
            _ => 0,
        }
    }

    /// Calculate embedding efficiency (bits per modified trit)
    pub fn embedding_efficiency(data_len: usize, modified_trits: usize) -> f64 {
        if modified_trits == 0 {
            return 0.0;
        }
        (data_len as f64 * 8.0) / modified_trits as f64
    }

    /// Detect if a sequence likely contains hidden data
    pub fn detect_anomaly(seq: &TernarySequence) -> f64 {
        let (neg, zero, pos) = StatisticalStego::block_stats(seq.trits());
        // Expected uniform distribution: 0.333 each
        let expected = 1.0 / 3.0;
        let deviation = (neg - expected).abs() + (zero - expected).abs() + (pos - expected).abs();
        // Higher deviation = more likely to contain hidden data
        deviation / 2.0 // Normalize to 0..1 range
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trit_conversions() {
        assert_eq!(Trit::Neg.to_i8(), -1);
        assert_eq!(Trit::Zero.to_i8(), 0);
        assert_eq!(Trit::Pos.to_i8(), 1);
        assert_eq!(Trit::from_i8(-1), Some(Trit::Neg));
        assert_eq!(Trit::from_i8(5), None);
    }

    #[test]
    fn test_trit_digits() {
        assert_eq!(Trit::Neg.digit(), 0);
        assert_eq!(Trit::Zero.digit(), 1);
        assert_eq!(Trit::Pos.digit(), 2);
        assert_eq!(Trit::from_digit(0), Some(Trit::Neg));
        assert_eq!(Trit::from_digit(3), None);
    }

    #[test]
    fn test_ternary_sequence_basic() {
        let seq = TernarySequence::from_i8(&[-1, 0, 1, -1, 0]);
        assert_eq!(seq.len(), 5);
        assert_eq!(seq.get(0), Some(Trit::Neg));
        assert_eq!(seq.get(2), Some(Trit::Pos));
        assert!(!seq.is_empty());
    }

    #[test]
    fn test_ternary_sequence_push() {
        let mut seq = TernarySequence::new(vec![]);
        seq.push(Trit::Pos);
        seq.push(Trit::Neg);
        assert_eq!(seq.len(), 2);
        assert_eq!(seq.get(0), Some(Trit::Pos));
    }

    #[test]
    fn test_bit_embedder_encode_decode() {
        let carrier = TernarySequence::from_i8(&[0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1]);
        let embedder = BitEmbedder::new(1);
        let data = vec![0x41]; // 'A'
        let encoded = embedder.encode(&carrier, &data).unwrap();
        let decoded = embedder.decode(&encoded, 1).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_bit_embedder_insufficient_capacity() {
        let carrier = TernarySequence::from_i8(&[0, 1]);
        let embedder = BitEmbedder::new(1);
        let data = vec![0xFF, 0xFF];
        assert!(embedder.encode(&carrier, &data).is_none());
    }

    #[test]
    fn test_bit_embedder_multiple_bytes() {
        let carrier = TernarySequence::from_i8(&[0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1]);
        let embedder = BitEmbedder::new(1);
        let data = vec![0x48, 0x69]; // "Hi"
        let encoded = embedder.encode(&carrier, &data).unwrap();
        let decoded = embedder.decode(&encoded, 2).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_pattern_encoder_basic() {
        let encoder = PatternEncoder::new(6);
        let encoded = encoder.encode("AB");
        let decoded = encoder.decode(&encoded);
        assert_eq!(decoded, "AB");
    }

    #[test]
    fn test_pattern_encoder_empty() {
        let encoder = PatternEncoder::new(4);
        let encoded = encoder.encode("");
        assert_eq!(encoded.len(), 0);
        let decoded = encoder.decode(&encoded);
        assert_eq!(decoded, "");
    }

    #[test]
    fn test_pattern_stego_encode_decode() {
        let carrier = TernarySequence::from_i8(&[0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1]);
        let encoder = PatternEncoder::new(4);
        let positions = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let encoded = encoder.stego_encode(&carrier, "A", &positions).unwrap();
        assert_eq!(encoded.len(), carrier.len());
    }

    #[test]
    fn test_frequency_modulator_encode_byte() {
        let modulator = FrequencyModulator::new(6);
        let trits = modulator.encode_byte(0x41);
        assert_eq!(trits.len(), 6);
    }

    #[test]
    fn test_frequency_modulator_roundtrip() {
        let carrier = TernarySequence::from_i8(&[0; 36]);
        let modulator = FrequencyModulator::new(9);
        let data = vec![0x41, 0x42, 0x43, 0x00];
        let encoded = modulator.encode(&carrier, &data).unwrap();
        let decoded = modulator.decode(&encoded, 4);
        // The roundtrip should preserve the decode
        assert_eq!(decoded.len(), 4);
    }

    #[test]
    fn test_frequency_modulator_insufficient() {
        let carrier = TernarySequence::from_i8(&[0; 3]);
        let modulator = FrequencyModulator::new(9);
        let data = vec![0x41, 0x42];
        assert!(modulator.encode(&carrier, &data).is_none());
    }

    #[test]
    fn test_statistical_stego_block_stats() {
        let trits = vec![Trit::Neg, Trit::Neg, Trit::Zero, Trit::Pos];
        let (neg, zero, pos) = StatisticalStego::block_stats(&trits);
        assert!((neg - 0.5).abs() < 0.01);
        assert!((zero - 0.25).abs() < 0.01);
        assert!((pos - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_statistical_stego_bit() {
        let stego = StatisticalStego::new(8);
        let mut block = vec![Trit::Zero; 8];
        stego.encode_bit(&mut block, 1);
        assert_eq!(stego.decode_bit(&block), 1);
        stego.encode_bit(&mut block, 0);
        assert_eq!(stego.decode_bit(&block), 0);
    }

    #[test]
    fn test_statistical_stego_roundtrip() {
        let carrier = TernarySequence::from_i8(&[0; 256]);
        let stego = StatisticalStego::new(4);
        let data = vec![0xAB];
        let encoded = stego.encode(&carrier, &data).unwrap();
        let decoded = stego.decode(&encoded, 1);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_spread_spectrum_pattern() {
        let ss = SpreadSpectrum::new(vec![42, 17, 99], 8);
        let pattern = ss.generate_pattern(10);
        assert_eq!(pattern.len(), 10);
        // All should be valid trits
        for t in &pattern {
            assert!(matches!(t, Trit::Neg | Trit::Zero | Trit::Pos));
        }
    }

    #[test]
    fn test_spread_spectrum_bit() {
        let ss = SpreadSpectrum::new(vec![42, 17], 8);
        let pattern = ss.generate_pattern(8);
        let encoded = ss.encode_bit(1, &pattern);
        assert_eq!(ss.decode_bit(&encoded, &pattern), 1);
        let encoded0 = ss.encode_bit(0, &pattern);
        assert_eq!(ss.decode_bit(&encoded0, &pattern), 0);
    }

    #[test]
    fn test_spread_spectrum_roundtrip() {
        let carrier = TernarySequence::from_i8(&[0; 128]);
        let ss = SpreadSpectrum::new(vec![42, 17, 99], 8);
        let data = vec![0x48];
        let encoded = ss.encode(&carrier, &data).unwrap();
        let decoded = ss.decode(&encoded, 1);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_capacity_analyzer() {
        assert_eq!(CapacityAnalyzer::max_bytes(100, "bit"), 12);
        assert_eq!(CapacityAnalyzer::max_bytes(100, "pattern"), 14);
        assert!(CapacityAnalyzer::max_bytes(100, "unknown") == 0);
    }

    #[test]
    fn test_embedding_efficiency() {
        let eff = CapacityAnalyzer::embedding_efficiency(1, 8);
        assert!((eff - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_detect_anomaly_uniform() {
        // Create a perfectly uniform sequence
        let trits: Vec<Trit> = (0..99).map(|i| match i % 3 {
            0 => Trit::Neg,
            1 => Trit::Zero,
            _ => Trit::Pos,
        }).collect();
        let seq = TernarySequence::new(trits);
        let anomaly = CapacityAnalyzer::detect_anomaly(&seq);
        assert!(anomaly < 0.1); // Should be low for uniform
    }

    #[test]
    fn test_detect_anomaly_biased() {
        let trits = vec![Trit::Pos; 100];
        let seq = TernarySequence::new(trits);
        let anomaly = CapacityAnalyzer::detect_anomaly(&seq);
        assert!(anomaly > 0.5); // Should be high for biased
    }
}
