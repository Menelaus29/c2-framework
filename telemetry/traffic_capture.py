import argparse
import subprocess
import signal
import sys
import time
import shutil

from common.logger import get_logger
from transport.traffic_profile import EvasionProfile
from datetime import datetime, timedelta, timezone

logger = get_logger('traffic_capture')

DEFAULT_BPF_FILTER = 'tcp port 443'
UTC_PLUS_7 = timezone(timedelta(hours=7))

def timestamp_utc7() -> str:
    # Return current timestamp formatted for filenames in UTC+7
    now = datetime.now(UTC_PLUS_7)
    return now.strftime('%Y%m%d_%H%M%S')

def start_capture(
    interface:   str,
    output_file: str,
    bpf_filter:  str = DEFAULT_BPF_FILTER,
) -> subprocess.Popen:
    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump not found on PATH")
    # Launch tcpdump on the given interface, write raw packets to output_file.
    cmd = ['tcpdump', '-n', '-i', interface, '-w', output_file] + bpf_filter.split()
    logger.info('starting capture', extra={
        'interface':   interface,
        'output_file': output_file,
        'bpf_filter':  bpf_filter,
    })
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,  # capture tcpdump stderr for error reporting
    )
    logger.info('capture started', extra={'pid': proc.pid})
    return proc


def stop_capture(proc: subprocess.Popen) -> None:
    # Terminate tcpdump and wait for the process to flush and exit.
    if proc.poll() is not None:
        # Already exited — nothing to do
        logger.warning('capture process already exited', extra={'returncode': proc.returncode})
        return

    logger.info('stopping capture', extra={'pid': proc.pid})
    proc.terminate()
    try:
        proc.wait(timeout=5)
        logger.info('capture stopped', extra={'pid': proc.pid, 'returncode': proc.returncode})
    except subprocess.TimeoutExpired:
        # tcpdump did not exit cleanly — force kill
        logger.warning('capture did not stop in time — sending SIGKILL', extra={'pid': proc.pid})
        proc.kill()
        proc.wait()


def label_capture(base_name: str, profile: EvasionProfile) -> str:
    # pcap filename builder
    ts = timestamp_utc7()
    return (
        f'{base_name}'
        f'_jitter{profile.jitter_pct}'
        f'_pad{profile.padding_max}'
        f'_{ts}'
        f'.pcap'
    )

# Self-test
if __name__ == '__main__':
    # Standalone usage (run from project root):
    #   python -m telemetry.traffic_capture --interface eth0 --output capture.pcap
    #   python -m telemetry.traffic_capture --interface eth0 --output capture.pcap --filter 'tcp port 8443'
    #   python -m telemetry.traffic_capture --interface eth0 --output capture.pcap --duration 10

    parser = argparse.ArgumentParser(
        description='PCAP capture wrapper. Requires tcpdump and sudo on Linux.',
    )
    parser.add_argument('--interface', required=True,  help='Network interface to capture on')
    parser.add_argument('--output',    required=True,  help='Output .pcap file path')
    parser.add_argument('--filter',    default=DEFAULT_BPF_FILTER, help='BPF filter expression')
    parser.add_argument('--duration',  type=int, default=0,
                        help='Capture duration in seconds (0 = until Ctrl+C)')
    args = parser.parse_args()

    proc = start_capture(args.interface, args.output, args.filter)

    # Allow clean exit on Ctrl+C
    def _handle_sigint(sig, frame):
        print('\nInterrupted — stopping capture...')
        stop_capture(proc)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    if args.duration > 0:
        print(f'Capturing for {args.duration}s on {args.interface} → {args.output}')
        time.sleep(args.duration)
        stop_capture(proc)
    else:
        print(f'Capturing on {args.interface} → {args.output} (Ctrl+C to stop)')
        proc.wait()