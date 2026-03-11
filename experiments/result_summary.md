# Beacon Variation Experiment — Results Summary

## Metric Definitions

| Metric | Description |
|--------|-------------|
| `beacon_iat_mean` | Mean time between consecutive TCP connection start times to the same destination. Reflects the base beacon interval plus any jitter applied by the active evasion profile. |
| `beacon_iat_std` | Population standard deviation of beacon inter-arrival times. The primary signal for jitter effectiveness — higher values indicate more timing variance and harder fingerprinting. |
| `entropy_mean` | Mean Shannon entropy computed from per-packet wire sizes across all flows in the capture. Approximates payload randomness; see Limitations. |
| `payload_len_mean` | Mean per-flow average packet size in bytes, including TLS record framing overhead. |

## Lab Notes

> **Beacon interval**: `BEACON_INTERVAL_S` was set to 5s for this experiment to produce sufficient
> samples (~35 beacons per profile) within the 180s capture window. Production default is 30s.
> IAT mean values reflect this instrumentation choice and are not representative of operational timing.

> **Capture interface**: Traffic was captured on `lo` (loopback) because the agent subprocess
> runs on the same host as the server during this experiment. In a two-machine deployment,
> `enp0s8` would be used instead. Flow features are interface-independent.

## Feature Statistics by Profile

| Profile | beacon_iat mean | beacon_iat std | entropy mean | entropy std | payload mean | payload std |
|---------|----------------|---------------|-------------|------------|-------------|------------|
| baseline | 5.0983 | 0.0318 | 2.1811 | 0.1242 | 345.2063 | 158.3464 |
| low | 5.0708 | 0.2771 | 2.1964 | 0.1534 | 344.1140 | 152.0404 |
| medium | 5.1602 | 1.0622 | 2.1970 | 0.1235 | 351.2477 | 153.8857 |
| high | 5.2024 | 1.7554 | 2.1711 | 0.1437 | 350.4224 | 146.8890 |

## Interpretations
Entropy is effectively identical across all profiles (~2.18–2.20) because all traffic is
TLS-encrypted; packet-size-based entropy is not a useful discriminator here.


**Baseline**: Baseline shows near-zero beacon IAT variance (std=0.032s) with no jitter configured —
variance reflects OS scheduling noise only. This highly regular timing pattern is trivially
fingerprinted by any network monitor computing inter-connection intervals.

**Low**: Low profile beacon IAT std is 8.7x baseline (0.277s), introducing measurable but modest
timing variation via 10% uniform jitter. Payload size (344.1 bytes mean) is within noise range of
baseline — TLS record framing at this payload size obscures application-layer padding differences.

**Medium**: Medium profile beacon IAT std is 33.4x baseline (1.062s) via 20% uniform jitter —
a substantial increase that would defeat simple fixed-threshold detectors. Payload differences
remain within noise range for the same TLS framing reason as above.

**High**: High profile beacon IAT std is 55.2x baseline (1.755s) via 40% Gaussian jitter —
the largest variance across all profiles and the clearest evasion signal.
 
The monotonic progression baseline → low → medium → high confirms the jitter pipeline is functioning as designed.
Payload and entropy metrics show no meaningful cross-profile variation at this payload scale, consistent with the known limitation of TLS obscuring application-layer padding at small sizes.

## Limitations

**Entropy approximation**: Shannon entropy is computed from per-packet wire sizes modulo 256,
not from actual payload bytes. Because all traffic is TLS-encrypted, ciphertext entropy is
uniformly high regardless of profile. Entropy is therefore not a useful cross-profile
discriminator in this experiment. Meaningful entropy analysis would require decrypted payload
bytes, which are unavailable at the capture layer by design.

**Payload size**: TLS record framing adds fixed per-record overhead (~29 bytes for TLS 1.3)
that is proportionally large relative to the beacon payload at this scale (~350 bytes total).
Application-layer padding differences of 0–256 bytes are partially obscured by this framing.
Payload size differences across profiles are within the noise range of per-flow variation and
should not be interpreted as evidence that padding is ineffective — only that it is not
detectable at the wire level via packet size alone at this payload scale.

**Same-host capture**: Agent and server ran on the same machine, so traffic was captured on `lo`
rather than crossing a physical network interface. RTT and packet timing characteristics on
loopback differ from a real network path. IAT variance ratios between profiles remain valid,
but absolute timing values are not representative of a real two-machine deployment.