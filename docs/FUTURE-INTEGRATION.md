# Future Integration: ternary-steganography

## Current State
Provides steganographic techniques for hiding information in ternary strategy noise: `BitEmbedder` (LSB-style embedding in trit sequences), pattern encoding, frequency modulation, statistical steganography, and `SpreadSpectrum` techniques. Operates on `Trit` values (-1, 0, +1).

## Integration Opportunities

### With ternary-protocol (Protocol Enrichment)
The cross-pollination report identifies this directly: ternary-protocol messages are trit sequences, and ternary-steganography embeds data in trit sequences. The carrier IS the protocol. Every `TernaryMessage` can carry hidden metadata: skill version, trust score, provenance hash. `BitEmbedder` in message payloads enables covert metadata. `SpreadSpectrum` creates tamper-evident messages — any modification destroys the hidden checksum, providing integrity verification distinct from error-correcting codes.

### With ternary-noise (Steganographic Noise)
ternary-noise injects noise into ternary signals at controlled SNR. ternary-steganography embeds data in ternary signals. The combination: use the noise floor as the steganographic channel. If the noise injection is expected (part of robustness training), hidden data embedded in the noise is invisible even to an adversary who knows noise injection is happening. `StatisticalStego` ensures the embedded data's statistical profile matches natural noise.

### With ternary-codes (Error-Correcting Steganography)
ternary-codes' Hamming encoding adds redundancy. The redundant trits (parity) are "free space" for steganographic embedding — they don't affect the decoded data. A `TernaryHamming` codeword with 2 data trits and 3 parity trits can carry 2 trits of hidden data in the parity positions without changing the decoded message.

## Potential in Mature Systems
In room-as-codespace, every ternary-protocol message between rooms carries both visible payload and hidden metadata. The visible data serves the fleet (task coordination, state sync). The hidden data serves security (provenance chain verification, trust scoring, anti-tamper checksums). PLATO's tile synchronization messages carry hidden checksums that verify tile integrity without exposing the verification mechanism to potential attackers.

## Cross-Pollination Ideas
- **ternary-adversarial**: Adversarial training should include steganographic detection — train strategies to be robust against hidden data in incoming messages.
- **ternary-streaming**: Detect steganographic content in streaming windows — statistical analysis of the stream reveals hidden patterns.
- **ternary-federated**: Federated learning participants can verify they're communicating with legitimate peers via shared steganographic keys embedded in strategy updates.

## Dependencies for Next Steps
- Define `SteganographicMessage` wrapper for ternary-protocol `TernaryMessage`
- Implement tamper-evident checksums using `SpreadSpectrum` in ternary-protocol
- Benchmark embedding/extraction overhead on ESP32
- Add steganographic detection to ternary-adversarial's attack suite
