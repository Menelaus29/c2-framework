import argparse
import dataclasses
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field

from scapy.all import PcapReader, IP, TCP, UDP

from common.logger import get_logger

logger = get_logger('flow_parser')

_PROTO_MAP = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


@dataclass
class FlowRecord:
    src_ip:               str
    dst_ip:               str
    src_port:             int
    dst_port:             int
    protocol:             str
    start_time:           float   # Unix timestamp of first packet
    end_time:             float   # Unix timestamp of last packet
    duration_s:           float
    packet_count:         int
    byte_count:           int
    inter_arrival_times:  list[float] = field(default_factory=list)
    payload_sizes:        list[int]   = field(default_factory=list)
    beacon_iats:          list[float] = field(default_factory=list)  # inter-flow gaps to same dst


def compute_beacon_iats(flows: list['FlowRecord']) -> None:
    # Group flows by (dst_ip, dst_port) and assign inter-flow start_time deltas as beacon_iats.
    # Each flow receives the IAT measured from its own start_time to the next flow's start_time
    # in the same group — capturing true beacon interval timing across TCP connections.
    groups: dict[tuple, list[FlowRecord]] = defaultdict(list)
    for flow in flows:
        # Only track client-initiated flows — high ephemeral src_port connecting to a low dst_port.
        # This excludes server-response flows (which have dst_port > 1024) from beacon IAT timing.
        if flow.src_port > 1024 and flow.dst_port <= 1024:
            groups[(flow.dst_ip, flow.dst_port)].append(flow)

    for group_flows in groups.values():
        group_flows.sort(key=lambda f: f.start_time)
        for i in range(len(group_flows) - 1):
            iat = round(group_flows[i + 1].start_time - group_flows[i].start_time, 6)
            # Assign to the earlier flow so each flow carries the gap that follows it
            group_flows[i].beacon_iats = [iat]

    logger.info('beacon iats computed', extra={'groups': len(groups), 'flows': len(flows)})


def parse_pcap(pcap_file: str) -> list[FlowRecord]:
    # Parse a PCAP file and return one FlowRecord per 5-tuple flow, with beacon_iats populated.
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f'PCAP file not found: {pcap_file}')

    logger.info('parsing pcap', extra={'pcap_file': pcap_file})

    flow_packets: dict[tuple, list] = defaultdict(list)
    total_packets = 0

    # Stream packets one at a time to avoid loading the entire PCAP into RAM
    with PcapReader(pcap_file) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            ip  = pkt[IP]
            ts  = float(pkt.time)
            src = ip.src
            dst = ip.dst

            if pkt.haslayer(TCP):
                layer    = pkt[TCP]
                proto    = 'TCP'
                src_port = layer.sport
                dst_port = layer.dport
            elif pkt.haslayer(UDP):
                layer    = pkt[UDP]
                proto    = 'UDP'
                src_port = layer.sport
                dst_port = layer.dport
            else:
                # Non-TCP/UDP — map protocol number to name where known
                proto    = _PROTO_MAP.get(ip.proto, str(ip.proto))
                src_port = 0
                dst_port = 0

            key = (src, dst, src_port, dst_port, proto)
            flow_packets[key].append((ts, len(pkt)))
            total_packets += 1

    if not flow_packets:
        logger.warning('no flows detected', extra={'pcap_file': pcap_file})
        return []

    flows = []
    for (src_ip, dst_ip, src_port, dst_port, protocol), entries in flow_packets.items():
        entries.sort(key=lambda x: x[0])   # sort by timestamp — not guaranteed in all PCAPs
        timestamps    = [ts   for ts, _    in entries]
        byte_counts   = [size for _,  size in entries]
        payload_sizes = byte_counts  # per-packet sizes for entropy and size feature computation

        start_time = timestamps[0]
        end_time   = timestamps[-1]
        duration_s = round(end_time - start_time, 6)

        # Time delta between each consecutive pair of packets in the flow
        iats = [
            round(timestamps[i] - timestamps[i - 1], 6)
            for i in range(1, len(timestamps))
        ]

        flows.append(FlowRecord(
            src_ip              = src_ip,
            dst_ip              = dst_ip,
            src_port            = src_port,
            dst_port            = dst_port,
            protocol            = protocol,
            start_time          = start_time,
            end_time            = end_time,
            duration_s          = duration_s,
            packet_count        = len(entries),
            byte_count          = sum(byte_counts),
            inter_arrival_times = iats,
            payload_sizes       = payload_sizes,
        ))

    compute_beacon_iats(flows)

    logger.info('parse complete', extra={
        'pcap_file':     pcap_file,
        'total_flows':   len(flows),
        'total_packets': total_packets,
    })
    return flows


def save_flows(flows: list[FlowRecord], output_file: str) -> None:
    # Write each FlowRecord as a JSON line to output_file.
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        for flow in flows:
            f.write(json.dumps(dataclasses.asdict(flow)) + '\n')

    logger.info('flows saved', extra={'output_file': output_file, 'count': len(flows)})


if __name__ == '__main__':
    # Standalone usage (run from project root):
    #   python -m telemetry.flow_parser --input capture.pcap --output capture.flows

    parser = argparse.ArgumentParser(
        description='Parse a PCAP file into FlowRecord JSON lines.',
    )
    parser.add_argument('--input',  required=True, help='Input .pcap file')
    parser.add_argument('--output', required=True, help='Output .flows file')
    args = parser.parse_args()

    flows = parse_pcap(args.input)
    save_flows(flows, args.output)
    print(f'Parsed {len(flows)} flows → {args.output}')