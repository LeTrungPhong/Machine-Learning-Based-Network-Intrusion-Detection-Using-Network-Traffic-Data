"""Tests for capture reading and packet field extraction (Phase 1)."""

from __future__ import annotations

import json
import random
from decimal import Decimal
from pathlib import Path

import pyarrow.csv as pa_csv
import pyarrow.parquet as pq
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP, fragment
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, CookedLinux, Dot1Q, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgWriter, PcapWriter

from preprocessing.extract_packets import (
    ACK, FIN, PACKET_SCHEMA, PSH, SYN, LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW,
    ParseStats, extract_packets, parse_frame,
)
from preprocessing.read_pcap import ReadStats, capture_format, iter_raw_frames
from utils.storage import InsufficientStorageError

TS = 1_499_428_779_599_128_000  # 2017-07-07 11:59:39.599128 UTC (first frame of CIC Friday capture)


def _parse(pkt: Packet, linktype: int = LINKTYPE_ETHERNET, stats: ParseStats | None = None):
    raw = bytes(pkt)
    return parse_frame(raw, linktype, TS, len(raw), stats)


def _sample_packets() -> list[Packet]:
    return [
        Ether() / IP(src="192.168.10.5", dst="8.8.8.8", ttl=64) / TCP(sport=51000, dport=443, flags="S", window=29200),
        Ether() / IP(src="8.8.8.8", dst="192.168.10.5") / TCP(sport=443, dport=51000, flags="SA") / Raw(b"x" * 100),
        Ether() / IP(src="192.168.10.5", dst="192.168.10.3") / UDP(sport=5353, dport=53) / Raw(b"q" * 30),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0) / Raw(b"p" * 56),
        Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=1234, dport=80, flags="PA") / Raw(b"GET /"),
        Ether() / ARP(),
    ]


# ---------------------------------------------------------------- parse_frame

def test_tcp_ipv4_fields() -> None:
    pkt = Ether() / IP(src="192.168.10.5", dst="8.8.8.8", ttl=64) / TCP(
        sport=51000, dport=443, flags="PA", window=1234) / Raw(b"a" * 100)
    rec = _parse(pkt)
    assert rec is not None
    assert (rec.src_ip, rec.dst_ip, rec.src_port, rec.dst_port, rec.protocol) == ("192.168.10.5", "8.8.8.8", 51000, 443, 6)
    assert rec.ip_version == 4 and rec.ttl == 64 and rec.tcp_window == 1234
    assert rec.tcp_flags == PSH | ACK
    assert rec.ip_header_len == 20 and rec.l4_header_len == 20 and rec.payload_len == 100
    assert rec.ip_len == 140 and rec.frame_len == 154
    assert rec.ts_ns == TS and not rec.truncated and not rec.is_fragment


def test_ethernet_padding_not_counted_as_payload() -> None:
    raw = bytes(Ether() / IP() / TCP(flags="A"))
    padded = raw + b"\x00" * (60 - len(raw))
    rec = parse_frame(padded, LINKTYPE_ETHERNET, TS, len(padded))
    assert rec is not None and rec.payload_len == 0 and rec.frame_len == 60


def test_tcp_options_change_header_length() -> None:
    rec = _parse(Ether() / IP() / TCP(flags="S", options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]))
    assert rec is not None and rec.l4_header_len == 28 and rec.payload_len == 0


def test_udp_and_icmp() -> None:
    udp = _parse(Ether() / IP() / UDP(sport=5353, dport=53) / Raw(b"q" * 30))
    assert udp is not None and udp.protocol == 17 and udp.dst_port == 53 and udp.payload_len == 30
    assert udp.tcp_flags == 0 and udp.tcp_window == -1
    icmp = _parse(Ether() / IP() / ICMP(type=3, code=1) / Raw(b"p" * 28))
    assert icmp is not None and (icmp.icmp_type, icmp.icmp_code) == (3, 1)
    assert icmp.src_port == 0 and icmp.payload_len == 28


def test_ipv6_with_extension_header() -> None:
    rec = _parse(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=33)
                 / IPv6ExtHdrHopByHop() / UDP(sport=1000, dport=2000) / Raw(b"z" * 10))
    assert rec is not None
    assert rec.ip_version == 6 and rec.src_ip == "2001:db8::1" and rec.ttl == 33
    assert rec.protocol == 17 and rec.dst_port == 2000 and rec.payload_len == 10
    assert rec.ip_header_len == 48


def test_vlan_qinq() -> None:
    rec = _parse(Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP(dst="1.2.3.4") / TCP(dport=22))
    assert rec is not None and rec.dst_ip == "1.2.3.4" and rec.dst_port == 22


def test_linux_sll_and_raw_ip_linktypes() -> None:
    sll = _parse(CookedLinux(proto=0x0800) / IP(dst="5.6.7.8") / UDP(dport=123), LINKTYPE_LINUX_SLL)
    assert sll is not None and sll.dst_ip == "5.6.7.8" and sll.dst_port == 123
    raw = _parse(IP(dst="9.9.9.9") / TCP(dport=853), LINKTYPE_RAW)
    assert raw is not None and raw.dst_port == 853


def test_ip_fragments() -> None:
    frags = fragment(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=7, dport=9) / Raw(b"d" * 3000), fragsize=1000)
    recs = [_parse(Ether() / f) for f in frags]
    assert all(r is not None and r.is_fragment for r in recs)
    assert recs[0].dst_port == 9 and recs[0].l4_header_len == 8
    assert all(r.src_port == 0 and r.l4_header_len == 0 for r in recs[1:])
    assert sum(r.payload_len for r in recs) == 3000


def test_tso_zero_total_length() -> None:
    raw = bytearray(bytes(Ether() / IP() / TCP() / Raw(b"k" * 2000)))
    raw[16:18] = b"\x00\x00"  # IPv4 total length field
    rec = parse_frame(bytes(raw), LINKTYPE_ETHERNET, TS)
    assert rec is not None and rec.payload_len == 2000


def test_non_ip_and_malformed_are_counted_not_raised() -> None:
    st = ParseStats()
    assert _parse(Ether() / ARP(), stats=st) is None
    full = bytes(Ether() / IP() / TCP())
    assert parse_frame(full[:20], LINKTYPE_ETHERNET, TS, stats=st) is None      # cut in IP header
    assert parse_frame(b"", LINKTYPE_ETHERNET, TS, stats=st) is None
    assert parse_frame(full, 9999, TS, stats=st) is None                         # unknown linktype
    assert (st.non_ip, st.malformed, st.unsupported_linktype, st.parsed) == (1, 2, 1, 0)


def test_truncated_l4_header_is_flagged() -> None:
    full = bytes(Ether() / IP() / TCP(dport=80) / Raw(b"y" * 50))
    rec = parse_frame(full[:40], LINKTYPE_ETHERNET, TS, len(full))
    assert rec is not None and rec.truncated and rec.dst_port == 0
    assert rec.payload_len == 50 and rec.frame_len == len(full)


def test_random_bytes_never_raise() -> None:
    rng = random.Random(0)
    base = bytes(Ether() / IP() / TCP() / Raw(b"r" * 20))
    st = ParseStats()
    for _ in range(3000):
        n = rng.randrange(0, len(base) + 10)
        data = bytes(rng.getrandbits(8) for _ in range(n)) if rng.random() < 0.5 else (
            base[:n] if n <= len(base) else base + b"\xff" * (n - len(base)))
        parse_frame(data, rng.choice([LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, 0]), TS, stats=st)
    assert st.parsed + st.non_ip + st.malformed + st.unsupported_linktype == 3000


def test_matches_scapy_dissection() -> None:
    for pkt in _sample_packets():
        rec = _parse(pkt)
        if ARP in pkt:
            assert rec is None
            continue
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        assert rec is not None
        assert rec.src_ip == ip.src and rec.dst_ip == ip.dst
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        if l4 is not None:
            assert (rec.src_port, rec.dst_port) == (l4.sport, l4.dport)
            assert rec.payload_len == len(l4.payload)
        if TCP in pkt:
            assert rec.tcp_flags == int(pkt[TCP].flags) and rec.tcp_window == pkt[TCP].window


# ---------------------------------------------------------------- read_pcap

def _write(path: Path, pkts: list[Packet], ng: bool = False, nano: bool = False) -> Path:
    writer = PcapNgWriter(str(path)) if ng else PcapWriter(str(path), nano=nano)
    for i, p in enumerate(pkts):
        p.time = Decimal(TS) / Decimal(10**9) + Decimal(i) / Decimal(1000)
        writer.write(p)
    writer.close()
    return path


@pytest.mark.parametrize("ng,nano,fmt", [(False, False, "pcap"), (False, True, "pcap"), (True, False, "pcapng")])
def test_reader_preserves_timestamps_and_count(tmp_path: Path, ng: bool, nano: bool, fmt: str) -> None:
    pkts = _sample_packets()
    path = _write(tmp_path / f"t.{fmt}", pkts, ng=ng, nano=nano)
    assert capture_format(path) == fmt
    st = ReadStats()
    frames = list(iter_raw_frames(path, stats=st))
    assert len(frames) == st.frames == len(pkts)
    assert [f.ts_ns for f in frames] == [TS + i * 1_000_000 for i in range(len(pkts))]
    assert all(f.linktype == LINKTYPE_ETHERNET for f in frames)
    assert frames[0].data == bytes(pkts[0])


def test_reader_max_packets(tmp_path: Path) -> None:
    path = _write(tmp_path / "t.pcap", _sample_packets())
    assert len(list(iter_raw_frames(path, max_packets=2))) == 2


def test_reader_stops_cleanly_on_truncated_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "t.pcap", _sample_packets())
    data = path.read_bytes()
    cut = tmp_path / "cut.pcap"
    n = len(_sample_packets())
    last_len = len(bytes(_sample_packets()[-1]))

    cut.write_bytes(data[:-10])                      # file ends inside the last packet's bytes
    st = ReadStats()
    frames = list(iter_raw_frames(cut, stats=st))
    assert len(frames) == n and st.truncated == 1 and st.read_error is None
    assert len(frames[-1].data) == last_len - 10 and frames[-1].wirelen == last_len

    cut.write_bytes(data[:-(last_len + 8)])          # file ends inside the last record header
    assert len(list(iter_raw_frames(cut))) == n - 1


def test_reader_rejects_non_capture(tmp_path: Path) -> None:
    p = tmp_path / "x.pcap"
    p.write_bytes(b"not a capture at all")
    with pytest.raises(ValueError):
        list(iter_raw_frames(p))
    with pytest.raises(FileNotFoundError):
        list(iter_raw_frames(tmp_path / "missing.pcap"))


# ---------------------------------------------------------------- export

def _cfg(min_free: float = 0.0) -> dict:
    return {"pcap": {"chunk_rows": 2, "export_formats": ["parquet", "csv"]},
            "storage": {"min_free_gb": min_free, "warn_free_gb": 0.0}}


def test_extract_packets_writes_parquet_csv_and_summary(tmp_path: Path) -> None:
    pkts = _sample_packets()
    pcap = _write(tmp_path / "s.pcapng", pkts, ng=True)
    summary = extract_packets(pcap, tmp_path / "out", _cfg())

    table = pq.read_table(summary.outputs["parquet"])
    assert table.schema.equals(PACKET_SCHEMA)
    assert table.num_rows == len(pkts) - 1           # ARP skipped
    assert table.column("ts_ns").to_pylist()[0] == TS
    assert table.column("timestamp").cast("int64").to_pylist() == table.column("ts_ns").to_pylist()
    assert table.column("tcp_flags").to_pylist()[:2] == [SYN, SYN | ACK]

    csv = pa_csv.read_csv(summary.outputs["csv"])
    assert csv.num_rows == table.num_rows
    assert csv.column("src_ip").to_pylist() == table.column("src_ip").to_pylist()

    js = json.loads((tmp_path / "out" / "s.packets.summary.json").read_text(encoding="utf-8"))
    assert js["read"]["frames"] == len(pkts) and js["parse"]["non_ip"] == 1
    assert js["first_ts_utc"] == "2017-07-07T11:59:39.599128000Z"


def test_extract_packets_refuses_when_disk_reserve_violated(tmp_path: Path) -> None:
    pcap = _write(tmp_path / "s.pcap", _sample_packets())
    with pytest.raises(InsufficientStorageError):
        extract_packets(pcap, tmp_path / "out", _cfg(min_free=1e9))


def test_fin_flag_constant_matches_scapy() -> None:
    rec = _parse(Ether() / IP() / TCP(flags="FA"))
    assert rec is not None and rec.tcp_flags == FIN | ACK
