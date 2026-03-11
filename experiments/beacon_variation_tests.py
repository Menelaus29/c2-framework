# Runs the full beacon cycle for each evasion profile, captures a PCAP, and extracts features.
# Prerequisites: both VMs running, Docker Compose up, agent reachable at BACKEND_PORT.
# Run from project root: python -m experiments.beacon_variation_tests

import os
import subprocess
import sys
import time
import argparse
import re

from common import config
from common.logger import get_logger
from telemetry import traffic_capture, flow_parser, feature_extractor

logger = get_logger('beacon_variation_tests')

PROFILES          = ['baseline', 'low', 'medium', 'high']
AGENT_DURATION_S  = 180                                        # 3 minutes per profile run
PROFILE_CONFIG    = os.path.join('evasion', 'profile_config.yaml')
INTERFACE         = 'enp0s8'                                   # host-only adapter on Ubuntu VM
SUMMARY_COLUMNS   = ('profile', 'mean_iat', 'std_iat', 'mean_payload', 'entropy')


def set_active_profile(profile_name: str) -> None:
    # Replace only the active_profile line in profile_config.yaml, preserving all comments and formatting.
    with open(PROFILE_CONFIG, 'r', encoding='utf-8') as f:
        content = f.read()

    updated = re.sub(
        r'^(active_profile:\s*).*$',
        rf'\g<1>{profile_name}',
        content,
        flags=re.MULTILINE,
    )

    if updated == content:
        raise ValueError(f'active_profile field not found in {PROFILE_CONFIG}')

    with open(PROFILE_CONFIG, 'w', encoding='utf-8') as f:
        f.write(updated)

    logger.info('active profile set', extra={'profile': profile_name})


def run_agent(duration_s: int) -> None:
    # Launch the agent as a subprocess and let it run for duration_s seconds, then terminate.
    env = {**os.environ, 'LAB_MODE': '1'}
    proc = subprocess.Popen(
        [sys.executable, '-m', 'agent.agent_main'],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    logger.info('agent started', extra={'pid': proc.pid, 'duration_s': duration_s})
    time.sleep(duration_s)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    logger.info('agent stopped', extra={'pid': proc.pid})


def run_profile(profile_name: str, interface: str = INTERFACE) -> dict | None:
    # Run the full capture → parse → extract pipeline for one profile; return summary row.
    logger.info('starting profile run', extra={'profile': profile_name})

    # Step 1 — set active profile
    set_active_profile(profile_name)

    # Step 2 — start PCAP capture
    pcap_filename = f'{profile_name}.pcap'
    # traffic_capture.start_capture resolves paths into pcaps/ internally
    capture_proc = traffic_capture.start_capture(
        interface   = interface,
        output_file = pcap_filename,
        bpf_filter  = f'tcp port {config.SERVER_PORT}',
    )
    pcap_path = os.path.join('pcaps', pcap_filename)

    # Step 3 — run agent for AGENT_DURATION_S
    try:
        run_agent(AGENT_DURATION_S)
    finally:
        # Step 4 — stop capture regardless of agent outcome
        traffic_capture.stop_capture(capture_proc)

    # Step 5 — parse PCAP
    flows = flow_parser.parse_pcap(pcap_path)
    if not flows:
        logger.warning('no flows parsed — skipping feature extraction', extra={'profile': profile_name})
        return None

    # Step 6 — extract features
    flows_path    = pcap_path.replace('.pcap', '.flows')
    flow_parser.save_flows(flows, flows_path)
    features_path = pcap_path.replace('.pcap', '.features.csv')
    features      = feature_extractor.extract_all(flows_path)

    # Step 7 — save features
    feature_extractor.save_features(features, features_path)
    logger.info('profile run complete', extra={
        'profile':  profile_name,
        'flows':    len(flows),
        'features': len(features),
    })

    if not features:
        return None

    # Compute summary stats across all flows for this profile
    mean_iats    = [f['mean_iat']         for f in features]
    std_iats     = [f['std_iat']          for f in features]
    payloads     = [f['payload_len_mean'] for f in features]
    entropies    = [f['shannon_entropy']  for f in features]

    def avg(vals):
        return sum(vals) / len(vals) if vals else 0.0

    return {
        'profile':      profile_name,
        'mean_iat':     round(avg(mean_iats), 4),
        'std_iat':      round(avg(std_iats),  4),
        'mean_payload': round(avg(payloads),  4),
        'entropy':      round(avg(entropies), 4),
    }


def print_summary(rows: list[dict]) -> None:
    # Print a fixed-width summary table to stdout.
    col_widths = {
        'profile':      10,
        'mean_iat':     12,
        'std_iat':      12,
        'mean_payload': 14,
        'entropy':      10,
    }
    header = '  '.join(c.ljust(col_widths[c]) for c in SUMMARY_COLUMNS)
    divider = '  '.join('-' * col_widths[c] for c in SUMMARY_COLUMNS)
    print('\n' + header)
    print(divider)
    for row in rows:
        if row is None:
            continue
        line = '  '.join(str(row.get(c, 'N/A')).ljust(col_widths[c]) for c in SUMMARY_COLUMNS)
        print(line)
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run beacon variation experiment across all evasion profiles.',
    )
    parser.add_argument(
        '--interface',
        default=INTERFACE,
        help=f'Network interface to capture on (default: {INTERFACE})',
    )
    cli_args = parser.parse_args()

    summary_rows = []

    for profile in PROFILES:
        try:
            row = run_profile(profile, interface=cli_args.interface)
            summary_rows.append(row)
        except Exception as e:
            logger.error('profile run failed', extra={'profile': profile, 'reason': str(e)})
            summary_rows.append(None)

    # Restore active_profile to medium after experiment so normal dev use is unaffected
    set_active_profile('medium')
    logger.info('active profile restored to medium')

    print_summary(summary_rows)