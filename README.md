# ternary-steganography: Hide and extract data in ternary signal sequences

Bit embedding, pattern encoding, frequency modulation, statistical steganography, and spread-spectrum techniques for encoding binary data within sequences of ternary values (−1, 0, +1).

## Why This Exists

Ternary strategy signals look like noise to an outside observer. That makes them a good carrier for hidden data. This crate implements five steganographic techniques that embed arbitrary bytes into ternary sequences without changing the sequence length. You can use it for watermarking strategy outputs, embedding metadata in decision streams, or building covert channels over ternary protocols.

## Core Concepts

- **Trit** — A ternary digit: `Neg` (−1), `Zero` (0), or `Pos` (+1). The fundamental unit of carrier data.
- **TernarySequence** — An ordered list of trits. The carrier medium for hidden data.
- **Bit embedding** — The simplest technique: each trit encodes one bit. `Pos` = 1, everything else = 0. Capacity: 1 bit per trit.
- **Pattern encoding** — Converts characters to base-3 digit sequences, then maps to trits. Can hide messages at arbitrary positions in the carrier.
- **Frequency modulation** — Encodes bytes by adjusting the ratio of Neg/Zero/Pos values within fixed-size windows. A window of N trits encodes one byte.
- **Statistical steganography** — Encodes bits by shifting the statistical balance of fixed-size blocks. Block has more Pos than Neg → bit 1; more Neg than Pos → bit 0.
- **Spread spectrum** — Encodes bits by multiplying a pseudo-random ternary pattern by +1 or −1. Decoding correlates with the same pattern. Robust against partial corruption.
- **Capacity analysis** — Compute maximum embeddable bytes and detect statistical anomalies that reveal hidden data.

## Quick Start

```toml
# Cargo.toml
[dependencies]
ternary-steganography = "0.1"
```

```rust
use ternary_steganography::*;

// Create a carrier sequence (24 trits = room for 3 bytes)
let carrier = TernarySequence::from_i8(&[0, 1, -1, 0, 1, -1, 0, 1,
                                          -1, 0, 1, -1, 0, 1, -1, 0,
                                          1, -1, 0, 1, -1, 0, 1, -1]);

// --- Bit embedding ---
let embedder = BitEmbedder::new(1);
let data = vec![0x48, 0x69]; // "Hi"
let encoded = embedder.encode(&carrier, &data).unwrap();
let decoded = embedder.decode(&encoded, 2).unwrap();
assert_eq!(decoded, data);

// --- Statistical steganography ---
let stego = StatisticalStego::new(4);
let encoded = stego.encode(&carrier, &vec![0xAB]).unwrap();
let decoded = stego.decode(&encoded, 1);
assert_eq!(decoded, vec![0xAB]);

// --- Check for anomalies ---
let anomaly = CapacityAnalyzer::detect_anomaly(&encoded);
println!("Anomaly score: {:.3} (higher = more likely to contain hidden data)", anomaly);
```

## API Overview

| Type | What it is |
|---|---|
| `Trit` | Ternary digit: `Neg`, `Zero`, `Pos` |
| `TernarySequence` | Ordered trit list; the carrier medium |
| `BitEmbedder` | 1-bit-per-trit embedding |
| `PatternEncoder` | Base-3 character encoding at arbitrary positions |
| `FrequencyModulator` | Windowed frequency-ratio encoding |
| `StatisticalStego` | Block-statistics encoding |
| `SpreadSpectrum` | Key-based spread-spectrum encoding |
| `CapacityAnalyzer` | Capacity and anomaly detection utilities |

## How It Works

**Bit embedding.** Maps each bit to a trit: bit 1 → `Pos`, bit 0 → `Neg`. Overwrites carrier trits sequentially. Decoding reads trits back and maps `Pos` → 1, everything else → 0. Simple but leaves obvious statistical traces (no `Zero` values in the encoded region).

**Pattern encoding.** Converts each character's Unicode code point to base-3 digits (using `Trit::digit()` mapping: Neg=0, Zero=1, Pos=2). Packs `pattern_len` trits per character. `stego_encode` places the encoded trits at specific positions in the carrier, leaving the rest untouched.

**Frequency modulation.** Each byte maps to a window of trits. The distribution of Neg/Zero/Pos within the window encodes the byte value: `neg_count + pos_count * 3 mod 256`. Decoding counts each trit type and reverses the formula.

**Statistical steganography.** Divides the carrier into blocks of `block_size` trits. To encode bit 1, fills the first half of the block with `Pos`. To encode bit 0, fills the first half with `Neg`. Decoding compares the fraction of Pos vs Neg. More robust than bit embedding because it doesn't change every trit.

**Spread spectrum.** Generates a pseudo-random ternary pattern from a key. To encode bit 1, the pattern is used as-is. For bit 0, each trit is negated (multiplied by −1). Decoding computes the dot product (correlation) between the received sequence and the pattern. Positive correlation → bit 1; negative → bit 0. Resistant to partial corruption because correlation integrates over the full chip sequence.

**Capacity analysis.** `max_bytes` estimates capacity based on technique and carrier length. `embedding_efficiency` computes bits per modified trit. `detect_anomaly` measures deviation from the expected uniform distribution (⅓ each) and returns a score in [0, 1]; higher scores suggest hidden data is present.

## Known Limitations

- **Bit embedding destroys the carrier.** Every trit in the encoded region becomes either `Pos` or `Neg`; `Zero` values are eliminated. This is trivially detectable by statistical analysis.
- **Frequency modulation is lossy.** The `neg_count + pos_count * 3 mod 256` formula can produce collisions—different bytes may map to the same trit distribution. Roundtrip fidelity is not guaranteed for all byte values.
- **Pattern encoding `stego_decode` has a bug.** The method extracts trits at the given positions but then constructs a new sequence from the full extraction (not truncated to `char_count × pattern_len`). In practice, use `encode`/`decode` directly rather than the stego helpers for pattern encoding.
- **No authentication or encryption.** Hidden data is not encrypted. Anyone who knows the technique and parameters can extract it. Use external encryption before embedding if secrecy matters.
- **Spread spectrum capacity is low.** With chip rate 8, each bit requires 8 trits. One byte = 64 trits. For high-capacity needs, use bit embedding or statistical steganography.

## Use Cases

- **Strategy watermarking.** Embed an identifier in a ternary strategy output. Later, extract it to prove which agent generated the sequence.
- **Covert metadata in decision streams.** Hide timestamps, version numbers, or tags in the ternary signals of an agent's decisions without adding separate metadata fields.
- **Anomaly detection.** Use `CapacityAnalyzer::detect_anomaly` to check whether a ternary signal stream has been tampered with or contains unexpected patterns.

## Ecosystem Context

Consumes `TernarySequence` data that may originate from `ternary-replay` (recorded sequences) or `ternary-pipeline` (processed output). No direct dependencies on other ternary crates.

## License

MIT
