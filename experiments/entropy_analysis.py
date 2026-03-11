# Loads per-profile feature CSVs from pcaps/, computes statistics, and saves results_summary.md.
import csv
import math
import os

from common.logger import get_logger

logger = get_logger('entropy_analysis')

PCAPS_DIR      = 'pcaps'
PROFILES       = ['baseline', 'low', 'medium', 'high']
METRICS        = ['mean_iat', 'std_iat', 'shannon_entropy', 'payload_len_mean']
RESULTS_PATH   = os.path.join('experiments', 'results_summary.md')


def _mean(values: list[float]) -> float:
    # Return arithmetic mean, or 0.0 if empty.
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float], mean: float) -> float:
    # Return population standard deviation, or 0.0 if fewer than 2 values.
    if len(values) < 2:
        return 0.0
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))


def load_features_csv(profile_name: str) -> list[dict]:
    # Load a profile's .features.csv and return rows as list of dicts with float values.
    path = os.path.join(PCAPS_DIR, f'{profile_name}.features.csv')
    if not os.path.exists(path):
        logger.warning('features file not found', extra={'path': path, 'profile': profile_name})
        return []

    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                rows.append({k: float(v) for k, v in row.items() if v != ''})
            except ValueError as e:
                logger.warning('skipping malformed row', extra={'reason': str(e)})
    logger.info('features loaded', extra={'profile': profile_name, 'rows': len(rows)})
    return rows


def compute_stats(rows: list[dict]) -> dict:
    # Compute mean and std for each metric across all rows.
    result = {}
    for metric in METRICS:
        values     = [r[metric] for r in rows if metric in r]
        m          = _mean(values)
        s          = _std(values, m)
        result[f'{metric}_mean'] = m
        result[f'{metric}_std']  = s
    return result


def _interpret(profile: str, stats: dict) -> str:
    # Generate a one-sentence interpretation of this profile's stats relative to baseline behaviour.
    mean_iat = stats.get('mean_iat_mean', 0)
    std_iat  = stats.get('std_iat_mean',  0)
    entropy  = stats.get('shannon_entropy_mean', 0)
    payload  = stats.get('payload_len_mean_mean', 0)

    if profile == 'baseline':
        return (
            f'Baseline shows near-zero IAT variance (std_iat={std_iat:.4f}), '
            f'uniform payload size ({payload:.1f} bytes), and entropy of {entropy:.4f} — '
            f'highly regular, easily fingerprinted beacon pattern.'
        )
    if profile == 'low':
        return (
            f'Low profile introduces slight IAT jitter (std_iat={std_iat:.4f}) '
            f'and mild padding (mean payload={payload:.1f} bytes); '
            f'entropy rises to {entropy:.4f} — detectable improvement over baseline.'
        )
    if profile == 'medium':
        return (
            f'Medium profile shows moderate IAT spread (std_iat={std_iat:.4f}, mean={mean_iat:.2f}s) '
            f'and increased payload variation ({payload:.1f} bytes mean); '
            f'entropy {entropy:.4f} — reasonable evasion for low-scrutiny environments.'
        )
    if profile == 'high':
        return (
            f'High profile produces the largest IAT variance (std_iat={std_iat:.4f}) '
            f'via Gaussian jitter, maximum padding ({payload:.1f} bytes mean), '
            f'and entropy {entropy:.4f} — hardest to fingerprint by timing alone.'
        )
    return f'Profile {profile}: mean_iat={mean_iat:.4f}, std_iat={std_iat:.4f}, entropy={entropy:.4f}.'


def print_table(profile_stats: dict[str, dict]) -> None:
    # Print a fixed-width comparison table to stdout.
    headers = ['profile', 'mean_iat_mean', 'mean_iat_std', 'std_iat_mean', 'std_iat_std',
               'entropy_mean', 'entropy_std', 'payload_mean', 'payload_std']
    col_w   = 15
    header_line = '  '.join(h.ljust(col_w) for h in headers)
    divider     = '  '.join('-' * col_w for _ in headers)
    print('\n' + header_line)
    print(divider)
    for profile in PROFILES:
        if profile not in profile_stats:
            continue
        stats = profile_stats[profile]
        row = [profile] + [
            f"{stats.get('mean_iat_mean',       0):.4f}",
            f"{stats.get('mean_iat_std',        0):.4f}",
            f"{stats.get('std_iat_mean',        0):.4f}",
            f"{stats.get('std_iat_std',         0):.4f}",
            f"{stats.get('shannon_entropy_mean',0):.4f}",
            f"{stats.get('shannon_entropy_std', 0):.4f}",
            f"{stats.get('payload_len_mean_mean',0):.4f}",
            f"{stats.get('payload_len_mean_std', 0):.4f}",
        ]
        print('  '.join(v.ljust(col_w) for v in row))
    print()


def save_markdown(profile_stats: dict[str, dict]) -> None:
    # Write results_summary.md with a Markdown table and per-profile interpretations.
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)

    lines = [
        '# Beacon Variation Experiment — Results Summary',
        '',
        '## Feature Statistics by Profile',
        '',
        '| Profile | mean_iat mean | mean_iat std | std_iat mean | std_iat std '
        '| entropy mean | entropy std | payload mean | payload std |',
        '|---------|--------------|-------------|-------------|------------|'
        '-------------|------------|-------------|------------|',
    ]

    for profile in PROFILES:
        if profile not in profile_stats:
            lines.append(f'| {profile} | — | — | — | — | — | — | — | — |')
            continue
        s = profile_stats[profile]
        lines.append(
            f"| {profile} "
            f"| {s.get('mean_iat_mean',        0):.4f} "
            f"| {s.get('mean_iat_std',         0):.4f} "
            f"| {s.get('std_iat_mean',         0):.4f} "
            f"| {s.get('std_iat_std',          0):.4f} "
            f"| {s.get('shannon_entropy_mean', 0):.4f} "
            f"| {s.get('shannon_entropy_std',  0):.4f} "
            f"| {s.get('payload_len_mean_mean',0):.4f} "
            f"| {s.get('payload_len_mean_std', 0):.4f} |"
        )

    lines += ['', '## Interpretations', '']

    for profile in PROFILES:
        if profile not in profile_stats:
            lines.append(f'**{profile}**: no data captured.')
            continue
        interp = _interpret(profile, profile_stats[profile])
        lines.append(f'**{profile.capitalize()}**: {interp}')
        lines.append('')

    with open(RESULTS_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    logger.info('results summary saved', extra={'path': RESULTS_PATH})


if __name__ == '__main__':
    profile_stats = {}

    for profile in PROFILES:
        rows = load_features_csv(profile)
        if not rows:
            logger.warning('no data for profile — skipping', extra={'profile': profile})
            continue
        profile_stats[profile] = compute_stats(rows)

    if not profile_stats:
        logger.error('no feature data found in pcaps/ — run beacon_variation_tests.py first')
    else:
        print_table(profile_stats)
        save_markdown(profile_stats)
        print(f'Results saved to {RESULTS_PATH}')