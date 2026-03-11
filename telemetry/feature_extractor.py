import argparse
import csv
import json
import math
import os

from common.logger import get_logger
from telemetry.flow_parser import FlowRecord

logger = get_logger('feature_extractor')

_SAFE_DIVISOR = 1e-9  # substituted for zero denominators to avoid division by zero


def shannon_entropy(data: bytes) -> float:
    # Compute Shannon entropy of a byte sequence using -sum(p*log2(p) for p > 0).
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts if c > 0
    )


def _mean(values: list[float]) -> float:
    # Return arithmetic mean of values, or 0.0 if empty.
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float], mean: float) -> float:
    # Return population standard deviation of values, or 0.0 if fewer than 2 values.
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _iat_autocorr(iats: list[float], mean: float, std: float) -> float:
    # Compute lag-1 autocorrelation of the IAT series; returns 0.0 if undefined.
    if len(iats) < 2 or std == 0.0:
        return 0.0
    n = len(iats)
    return sum(
        (iats[i] - mean) * (iats[i - 1] - mean)
        for i in range(1, n)
    ) / ((n - 1) * std ** 2)


def extract_features(flow: FlowRecord) -> dict:
    # Extract all timing, flow, size, and entropy features from a FlowRecord.
    iats     = flow.inter_arrival_times
    n        = flow.packet_count
    duration = flow.duration_s

    # --- Timing features ---
    mean_iat  = _mean(iats)
    std_iat   = _std(iats, mean_iat)
    min_iat   = min(iats) if iats else 0.0
    max_iat   = max(iats) if iats else 0.0
    # burstiness: coefficient of variation of IAT — high value means bursty, low means regular
    burstiness  = std_iat / mean_iat if mean_iat > 0 else 0.0
    iat_autocorr = _iat_autocorr(iats, mean_iat, std_iat)

    # --- Flow features ---
    safe_duration = duration if duration > 0 else _SAFE_DIVISOR
    bytes_per_second   = flow.byte_count   / safe_duration
    packets_per_second = n / safe_duration

    # --- Size features ---
    # byte_count / packet_count approximates mean payload size when raw bytes unavailable
    safe_n           = n if n > 0 else _SAFE_DIVISOR
    sizes            = [float(s) for s in flow.payload_sizes] if flow.payload_sizes else []
    payload_len_mean = _mean(sizes) if sizes else flow.byte_count / safe_n
    payload_len_std  = _std(sizes, payload_len_mean) if sizes else 0.0
    payload_len_min  = float(min(sizes)) if sizes else 0.0
    payload_len_max  = float(max(sizes)) if sizes else 0.0

    # Entropy approximation — encodes per-packet sizes as bytes since FlowRecord
    # stores no raw payload. For TLS traffic this underestimates true entropy
    # but is sufficient since all beacon captures are encrypted uniformly
    size_bytes = bytes([s % 256 for s in flow.payload_sizes]) if flow.payload_sizes else b''
    entropy    = shannon_entropy(size_bytes)

    return {
        'src_ip':              flow.src_ip,
        'dst_ip':              flow.dst_ip,
        'src_port':            flow.src_port,
        'dst_port':            flow.dst_port,
        'protocol':            flow.protocol,
        'mean_iat':            mean_iat,
        'std_iat':             std_iat,
        'min_iat':             min_iat,
        'max_iat':             max_iat,
        'burstiness':          burstiness,
        'iat_autocorr':        iat_autocorr,
        'flow_duration_s':     duration,
        'total_bytes':         flow.byte_count,
        'total_packets':       n,
        'bytes_per_second':    bytes_per_second,
        'packets_per_second':  packets_per_second,
        'payload_len_mean':    payload_len_mean,
        'payload_len_std':     payload_len_std,
        'payload_len_min':     payload_len_min,
        'payload_len_max':     payload_len_max,
        'shannon_entropy':     entropy,
    }


def extract_all(flows_file: str) -> list[dict]:
    # Load a .flows file and return extracted features for every flow.
    if not os.path.exists(flows_file):
        raise FileNotFoundError(f'.flows file not found: {flows_file}')

    features = []
    with open(flows_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw  = json.loads(line)
            flow = FlowRecord(**raw)
            features.append(extract_features(flow))

    logger.info('features extracted', extra={
        'flows_file': flows_file,
        'count':      len(features),
    })

    if not features:
        logger.warning('no features extracted', extra={'flows_file': flows_file})

    return features


def save_features(features: list[dict], output_file: str) -> None:
    # Write features to both a CSV file and a JSON lines file.
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    # CSV — derive base path by stripping .csv suffix if present
    csv_path  = output_file if output_file.endswith('.csv') else output_file + '.csv'
    json_path = csv_path.replace('.csv', '.json')

    if features:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=features[0].keys())
            writer.writeheader()
            writer.writerows(features)

    with open(json_path, 'w', encoding='utf-8') as f:
        for feat in features:
            f.write(json.dumps(feat) + '\n')

    logger.info('features saved', extra={
        'csv':   csv_path,
        'json':  json_path,
        'count': len(features),
    })


if __name__ == '__main__':
    # Standalone usage (run from project root):
    #   python -m telemetry.feature_extractor --input capture.flows --output capture.features.csv

    parser = argparse.ArgumentParser(
        description='Extract per-flow features from a .flows file.',
    )
    parser.add_argument('--input',  required=True, help='Input .flows file')
    parser.add_argument('--output', required=True, help='Output .csv file (JSON also written alongside)')
    args = parser.parse_args()

    features = extract_all(args.input)
    save_features(features, args.output)
    print(f'Extracted {len(features)} feature vectors → {args.output}')