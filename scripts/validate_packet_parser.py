"""Cross-check :func:`parse_frame` against full Scapy dissection on a real capture.

Usage:
    python scripts/validate_packet_parser.py --pcap <file> [--max-packets 20000]

Reports every field mismatch and the time spent reading vs. parsing.
Exit status is 1 if any mismatch is found.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from preprocessing.extract_packets import ParseStats, parse_frame  # noqa: E402
from preprocessing.read_pcap import iter_raw_frames  # noqa: E402


def compare(data: bytes, rec) -> list[str]:
    """Return names of fields where our record differs from Scapy's dissection."""
    pkt = Ether(data)
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        return [] if rec is None else ["non_ip_parsed"]
    if rec is None:
        return ["ip_not_parsed"]
    bad = []
    if (rec.src_ip, rec.dst_ip) != (ip.src, ip.dst):
        bad.append("ip")
    is_v4 = IP in pkt
    first_frag = not is_v4 or ip.frag == 0
    if is_v4 and rec.protocol != ip.proto:
        bad.append("protocol")
    if is_v4 and rec.ttl != ip.ttl:
        bad.append("ttl")
    if TCP in pkt and first_frag:
        t = pkt[TCP]
        if (rec.src_port, rec.dst_port) != (t.sport, t.dport):
            bad.append("tcp_ports")
        if rec.tcp_flags != int(t.flags):
            bad.append("tcp_flags")
        if rec.tcp_window != t.window:
            bad.append("tcp_window")
        if rec.l4_header_len != t.dataofs * 4:
            bad.append("tcp_hdr")
        if is_v4 and rec.payload_len != ip.len - ip.ihl * 4 - t.dataofs * 4:
            bad.append("tcp_payload")
    elif UDP in pkt and first_frag:
        u = pkt[UDP]
        if (rec.src_port, rec.dst_port) != (u.sport, u.dport):
            bad.append("udp_ports")
        # On a fragmented datagram udp.len covers the reassembled payload, not this packet.
        fragmented = is_v4 and bool(ip.flags.MF)
        if u.len >= 8 and not fragmented and rec.payload_len != u.len - 8:
            bad.append("udp_payload")
    elif ICMP in pkt and (rec.icmp_type, rec.icmp_code) != (pkt[ICMP].type, pkt[ICMP].code):
        bad.append("icmp")
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--max-packets", type=int, default=20000)
    args = ap.parse_args(argv)

    t0 = time.perf_counter()
    frames = list(iter_raw_frames(args.pcap, args.max_packets))
    t_read = time.perf_counter() - t0

    st = ParseStats()
    t0 = time.perf_counter()
    recs = [parse_frame(f.data, f.linktype, f.ts_ns, f.wirelen, st) for f in frames]
    t_parse = time.perf_counter() - t0

    t0 = time.perf_counter()
    mismatches: Counter[str] = Counter()
    examples: dict[str, int] = {}
    for i, (f, r) in enumerate(zip(frames, recs)):
        for name in compare(f.data, r):
            mismatches[name] += 1
            examples.setdefault(name, i)
    t_scapy = time.perf_counter() - t0

    n = len(frames)
    print(f"frames={n:,} parsed={st.parsed:,} non_ip={st.non_ip:,} malformed={st.malformed:,}")
    print(f"read:   {t_read:6.2f}s  ({n / t_read:,.0f} frames/s)")
    print(f"parse:  {t_parse:6.2f}s  ({n / t_parse:,.0f} frames/s)  <- struct parser")
    print(f"scapy:  {t_scapy:6.2f}s  ({n / t_scapy:,.0f} frames/s)  <- full Scapy dissection, for comparison")
    if mismatches:
        print("MISMATCHES:", dict(mismatches), "first index:", examples)
        return 1
    print("mismatches: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
