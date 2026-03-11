# Beacon Variation Experiment — Results Summary

> **Metric note**: `beacon_iat` measures time between consecutive TCP connection
> start times to the same destination — true beacon interval timing.
> `shannon_entropy` and `payload_len_mean` are per-flow averages across all flows in the capture.

> **Lab note**: `BEACON_INTERVAL_S` was set to 5s for this experiment to produce sufficient
> samples (~35 beacons per profile) within the 180s capture window. Production default is 30s.
> IAT mean values reflect this instrumentation choice and are not representative of operational timing.

## Feature Statistics by Profile

| Profile | beacon_iat mean | beacon_iat std | entropy mean | entropy std | payload mean | payload std |
|---------|----------------|---------------|-------------|------------|-------------|------------|
| baseline | 5.0983 | 0.0318 | 2.1811 | 0.1242 | 345.2063 | 158.3464 |
| low | 5.0708 | 0.2771 | 2.1964 | 0.1534 | 344.1140 | 152.0404 |
| medium | 5.1602 | 1.0622 | 2.1970 | 0.1235 | 351.2477 | 153.8857 |
| high | 5.2024 | 1.7554 | 2.1711 | 0.1437 | 350.4224 | 146.8890 |

## Interpretations

**Baseline**: Baseline shows near-zero beacon IAT variance (std=0.032s) with no jitter configured —
variance reflects OS scheduling noise only. This highly regular timing pattern is trivially
fingerprinted by any network monitor computing inter-connection intervals.

**Low**: Low profile beacon IAT std is 8.7x baseline (0.277s), introducing measurable but modest
timing variation via 10% uniform jitter. Payload size (344.1 bytes mean) is within noise range of
baseline — TLS record framing at this payload size obscures application-layer padding differences.
Entropy is effectively identical across all profiles (~2.18–2.20) because all traffic is
TLS-encrypted; packet-size-based entropy is not a useful discriminator here.

**Medium**: Medium profile beacon IAT std is 33.4x baseline (1.062s) via 20% uniform jitter —
a substantial increase that would defeat simple fixed-threshold detectors. Payload differences
remain within noise range for the same TLS framing reason as above.

**High**: High profile beacon IAT std is 55.2x baseline (1.755s) via 40% Gaussian jitter —
the largest variance across all profiles and the clearest evasion signal. The monotonic progression
baseline → low → medium → high confirms the jitter pipeline is functioning as designed.
Payload and entropy metrics show no meaningful cross-profile variation at this payload scale,
consistent with the known limitation of TLS obscuring application-layer padding at small sizes.