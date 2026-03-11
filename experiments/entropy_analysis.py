# Loads per-profile feature CSVs and flow files from pcaps/, computes statistics, and saves results_summary.md.
import csv
import json
import math
import os

from common.logger import get_logger

logger = get_logger('entropy_analysis')

PCAPS_DIR    = 'pcaps'
PROFILES     = ['baseline', 'low', 'medium', 'high']
RESULTS_PATH = os.path.join('experiments', 'results_summary.md')

# Metrics sourced from .features.csv
_CSV_METRICS   = ['shannon_entropy', 'payload_len_mean']
# Metrics sourced from .flows (beacon_iats field on FlowRecord)
_FLOWS_METRICS = ['beacon_iat']


def _mean(values: list[float]) -> float:
    # Return arithmetic mean, or 0.0 if empty.
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float], mean: float) -> float:
    # Return population standard deviation, or 0.0 if fewer than 2 values.
    if len(values) < 2:
        return 0.0
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))


def load_features_csv(profile_name: str) -> list[dict]:
    # Load a profile's .features.csv and return only the numeric metrics needed for analysis.
    path = os.path.join(PCAPS_DIR, f'{profile_name}.features.csv')
    if not os.path.exists(path):
        logger.warning('features file not found', extra={'path': path, 'profile': profile_name})
        return []

    _FLOAT_COLS = {'shannon_entropy', 'payload_len_mean'}
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                parsed = {k: float(v) for k, v in row.items() if k in _FLOAT_COLS and v != ''}
                if parsed:
                    rows.append(parsed)
            except ValueError as e:
                logger.warning('skipping malformed csv row', extra={'reason': str(e)})

    logger.info('csv features loaded', extra={'profile': profile_name, 'rows': len(rows)})
    return rows


def load_beacon_iats(profile_name: str) -> list[float]:
    # Load all beacon_iats from a profile's .flows file and return them as a flat list.
    path = os.path.join(PCAPS_DIR, f'{profile_name}.flows')
    if not os.path.exists(path):
        logger.warning('flows file not found', extra={'path': path, 'profile': profile_name})
        return []

    iats = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                iats.extend(record.get('beacon_iats', []))
            except json.JSONDecodeError as e:
                logger.warning('skipping malformed flow line', extra={'reason': str(e)})

    logger.info('beacon iats loaded', extra={'profile': profile_name, 'count': len(iats)})
    return iats


def compute_stats(csv_rows: list[dict], beacon_iats: list[float]) -> dict:
    # Compute mean and std for each metric across all rows and beacon IATs.
    result = {}

    for metric in _CSV_METRICS:
        values             = [r[metric] for r in csv_rows if metric in r]
        m                  = _mean(values)
        result[f'{metric}_mean'] = m
        result[f'{metric}_std']  = _std(values, m)

    m = _mean(beacon_iats)
    result['beacon_iat_mean'] = m
    result['beacon_iat_std']  = _std(beacon_iats, m)

    return result


def _interpret(profile: str, stats: dict, baseline_stats: dict | None) -> str:
    # Generate an interpretation comparing this profile's beacon IAT and payload stats to baseline.
    b_iat_mean = stats.get('beacon_iat_mean', 0)
    b_iat_std  = stats.get('beacon_iat_std',  0)
    entropy    = stats.get('shannon_entropy_mean', 0)
    payload    = stats.get('payload_len_mean_mean', 0)

    if profile == 'baseline':
        return (
            f'Baseline shows beacon IAT std of {b_iat_std:.3f}s (mean interval {b_iat_mean:.1f}s) '
            f'with no jitter configured — any variance reflects OS scheduling noise. '
            f'Payload mean is {payload:.1f} bytes, entropy {entropy:.4f}.'
        )

    # Compute ratio vs baseline for jitter commentary
    base_std = baseline_stats.get('beacon_iat_std', 0) if baseline_stats else 0
    if base_std > 0:
        ratio = b_iat_std / base_std
        ratio_str = f'{ratio:.1f}x baseline std_iat'
    else:
        ratio_str = f'std_iat={b_iat_std:.3f}s'

    if profile == 'low':
        return (
            f'Low profile beacon IAT std is {ratio_str} ({b_iat_std:.3f}s), '
            f'mean interval {b_iat_mean:.1f}s. '
            f'Mild padding raises payload to {payload:.1f} bytes; entropy {entropy:.4f}.'
        )
    if profile == 'medium':
        return (
            f'Medium profile beacon IAT std is {ratio_str} ({b_iat_std:.3f}s), '
            f'mean interval {b_iat_mean:.1f}s. '
            f'Increased padding yields {payload:.1f} bytes mean payload; entropy {entropy:.4f}.'
        )
    if profile == 'high':
        return (
            f'High profile beacon IAT std is {ratio_str} ({b_iat_std:.3f}s) via Gaussian jitter — '
            f'the largest variance across all profiles. '
            f'Maximum padding raises payload to {payload:.1f} bytes; entropy {entropy:.4f}.'
        )
    return (
        f'Profile {profile}: beacon_iat_mean={b_iat_mean:.3f}s, '
        f'beacon_iat_std={b_iat_std:.3f}s, entropy={entropy:.4f}.'
    )


def print_table(profile_stats: dict[str, dict]) -> None:
    # Print a fixed-width comparison table to stdout.
    headers = [
        'profile',
        'beacon_iat_mean', 'beacon_iat_std',
        'entropy_mean',    'entropy_std',
        'payload_mean',    'payload_std',
    ]
    col_w       = 17
    header_line = '  '.join(h.ljust(col_w) for h in headers)
    divider     = '  '.join('-' * col_w for _ in headers)
    print('\n' + header_line)
    print(divider)
    for profile in PROFILES:
        if profile not in profile_stats:
            continue
        s = profile_stats[profile]
        row = [profile] + [
            f"{s.get('beacon_iat_mean',       0):.4f}",
            f"{s.get('beacon_iat_std',        0):.4f}",
            f"{s.get('shannon_entropy_mean',  0):.4f}",
            f"{s.get('shannon_entropy_std',   0):.4f}",
            f"{s.get('payload_len_mean_mean', 0):.4f}",
            f"{s.get('payload_len_mean_std',  0):.4f}",
        ]
        print('  '.join(v.ljust(col_w) for v in row))
    print()


def save_markdown(profile_stats: dict[str, dict]) -> None:
    # Write results_summary.md with a Markdown table and per-profile interpretations.
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)

    lines = [
        '# Beacon Variation Experiment — Results Summary',
        '',
        '> **Metric note**: `beacon_iat` measures time between consecutive TCP connection',
        '> start times to the same destination — true beacon interval timing.',
        '> `shannon_entropy` and `payload_len_mean` are per-flow averages.',
        '',
        '## Feature Statistics by Profile',
        '',
        '| Profile | beacon_iat mean | beacon_iat std '
        '| entropy mean | entropy std | payload mean | payload std |',
        '|---------|----------------|---------------|'
        '-------------|------------|-------------|------------|',
    ]

    for profile in PROFILES:
        if profile not in profile_stats:
            lines.append(f'| {profile} | — | — | — | — | — | — |')
            continue
        s = profile_stats[profile]
        lines.append(
            f"| {profile} "
            f"| {s.get('beacon_iat_mean',       0):.4f} "
            f"| {s.get('beacon_iat_std',        0):.4f} "
            f"| {s.get('shannon_entropy_mean',  0):.4f} "
            f"| {s.get('shannon_entropy_std',   0):.4f} "
            f"| {s.get('payload_len_mean_mean', 0):.4f} "
            f"| {s.get('payload_len_mean_std',  0):.4f} |"
        )

    lines += ['', '## Interpretations', '']

    baseline_stats = profile_stats.get('baseline')
    for profile in PROFILES:
        if profile not in profile_stats:
            lines.append(f'**{profile.capitalize()}**: no data captured.')
            lines.append('')
            continue
        interp = _interpret(profile, profile_stats[profile], baseline_stats)
        lines.append(f'**{profile.capitalize()}**: {interp}')
        lines.append('')

    with open(RESULTS_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    logger.info('results summary saved', extra={'path': RESULTS_PATH})


if __name__ == '__main__':
    profile_stats = {}

    for profile in PROFILES:
        csv_rows    = load_features_csv(profile)
        beacon_iats = load_beacon_iats(profile)

        if not csv_rows and not beacon_iats:
            logger.warning('no data for profile — skipping', extra={'profile': profile})
            continue

        profile_stats[profile] = compute_stats(csv_rows, beacon_iats)

    if not profile_stats:
        logger.error('no feature data found in pcaps/ — run beacon_variation_tests.py first')
    else:
        print_table(profile_stats)
        save_markdown(profile_stats)
        print(f'Results saved to {RESULTS_PATH}')