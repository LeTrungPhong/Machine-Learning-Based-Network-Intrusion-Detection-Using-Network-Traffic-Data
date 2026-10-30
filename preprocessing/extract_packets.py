"""Packet-level field extraction and export to Parquet / CSV.

:func:`parse_frame` decodes link, network and transport headers with
``struct`` directly from raw bytes. It is used both for offline captures and
for live packets (``bytes(scapy_packet)``), so training and real-time
detection share exactly the same packet schema.

Lengths follow CICFlowMeter conventions: ``payload_len`` is the transport
payload size computed from the IP length fields (not from the captured
bytes), so Ethernet padding and snaplen truncation do not distort it.

Usage:
    python -m preprocessing.extract_packets --pcap <file> [--max-packets N] [--formats parquet csv]
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, NamedTuple

import pyarrow as pa
import pyarrow.csv as pa_csv
import pyarrow.parquet as pq

from preprocessing.read_pcap import ReadStats, RawFrame, capture_format, iter_raw_frames
from utils.storage import ensure_free_space

logger = logging.getLogger(__name__)

# Link-layer types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALT = 12          # DLT_RAW on some BSDs
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = {0x8100, 0x88A8, 0x9100}

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
IPV6_EXT_HEADERS = {0, 43, 60}   # hop-by-hop, routing, destination options
IPV6_FRAGMENT = 44

# TCP flag bits (NS stored in bit 8)
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100
TCP_FLAG_NAMES: dict[str, int] = {
    "FIN": FIN, "SYN": SYN, "RST": RST, "PSH": PSH, "ACK": ACK,
    "URG": URG, "ECE": ECE, "CWR": CWR, "NS": NS,
}

_U16 = struct.Struct("!H")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_IPV6 = struct.Struct("!IHBB16s16s")
_TCP = struct.Struct("!HHIIBBH")
_UDP = struct.Struct("!HHHH")


class PacketRecord(NamedTuple):
    """Decoded header fields of one IP packet (column order of the output schema)."""

    ts_ns: int
    ip_version: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    frame_len: int        # length on the wire
    ip_len: int           # IP header + IP payload
    ip_header_len: int
    l4_header_len: int    # TCP/UDP/ICMP header length, 0 if not parsed
    payload_len: int      # transport payload bytes
    ttl: int
    tcp_flags: int        # bit mask, see TCP_FLAG_NAMES; 0 for non-TCP
    tcp_window: int       # -1 for non-TCP
    icmp_type: int        # -1 for non-ICMP
    icmp_code: int
    is_fragment: bool
    truncated: bool       # captured bytes ended before the L4 header


PACKET_SCHEMA = pa.schema([
    ("ts_ns", pa.int64()),
    ("timestamp", pa.timestamp("ns", tz="UTC")),
    ("ip_version", pa.uint8()),
    ("src_ip", pa.string()),
    ("dst_ip", pa.string()),
    ("src_port", pa.int32()),
    ("dst_port", pa.int32()),
    ("protocol", pa.uint8()),
    ("frame_len", pa.int32()),
    ("ip_len", pa.int32()),
    ("ip_header_len", pa.int16()),
    ("l4_header_len", pa.int16()),
    ("payload_len", pa.int32()),
    ("ttl", pa.int16()),
    ("tcp_flags", pa.int16()),
    ("tcp_window", pa.int32()),
    ("icmp_type", pa.int16()),
    ("icmp_code", pa.int16()),
    ("is_fragment", pa.bool_()),
    ("truncated", pa.bool_()),
])


@dataclass
class ParseStats:
    """Counters for frames that could not be turned into a :class:`PacketRecord`."""

    parsed: int = 0
    non_ip: int = 0
    unsupported_linktype: int = 0
    malformed: int = 0
    truncated_l4: int = 0
    protocols: dict[int, int] = field(default_factory=dict)

    def count(self, rec: PacketRecord) -> None:
        self.parsed += 1
        self.protocols[rec.protocol] = self.protocols.get(rec.protocol, 0) + 1
        if rec.truncated:
            self.truncated_l4 += 1


def _l3_offset(data: bytes, linktype: int) -> tuple[int, int] | None:
    """Return ``(ethertype, offset)`` of the network header, or ``None`` if not IP-bearing."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        off = 12
        ethertype = _U16.unpack_from(data, off)[0]
        off = 14
        while ethertype in ETH_VLAN:        # 802.1Q / QinQ tags
            if len(data) < off + 4:
                return None
            ethertype = _U16.unpack_from(data, off + 2)[0]
            off += 4
        return ethertype, off
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None
        version = data[0] >> 4
        return (ETH_IPV4 if version == 4 else ETH_IPV6 if version == 6 else 0), 0
    if linktype == LINKTYPE_LINUX_SLL:
        return (_U16.unpack_from(data, 14)[0], 16) if len(data) >= 16 else None
    if linktype == LINKTYPE_LINUX_SLL2:
        return (_U16.unpack_from(data, 0)[0], 20) if len(data) >= 20 else None
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        family = struct.unpack_from("<I", data, 0)[0]
        if family > 0xFFFF:                 # written on a big-endian host
            family = struct.unpack_from(">I", data, 0)[0]
        if family == 2:
            return ETH_IPV4, 4
        if family in (10, 24, 28, 30):      # AF_INET6 on Linux/BSD/macOS
            return ETH_IPV6, 4
        return 0, 4
    return None


def parse_frame(data: bytes, linktype: int, ts_ns: int, wirelen: int | None = None,
                stats: ParseStats | None = None) -> PacketRecord | None:
    """Decode one captured frame.

    Never raises on bad input: non-IP frames, unsupported link types and
    malformed headers return ``None`` and are counted in ``stats``.

    Args:
        data: Captured bytes starting at the link-layer header.
        linktype: LINKTYPE of the capture interface.
        ts_ns: Capture timestamp in nanoseconds.
        wirelen: Original frame length; defaults to ``len(data)``.
        stats: Optional counters updated in place.
    """
    st = stats if stats is not None else ParseStats()
    try:
        l3 = _l3_offset(data, linktype)
        if l3 is None:
            if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_IPV4,
                                LINKTYPE_IPV6, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2, LINKTYPE_NULL):
                st.unsupported_linktype += 1
            else:
                st.malformed += 1
            return None
        ethertype, off = l3
        frame_len = wirelen if wirelen is not None else len(data)

        if ethertype == ETH_IPV4:
            if len(data) < off + 20:
                st.malformed += 1
                return None
            ver_ihl, _tos, total_len, _ident, frag, ttl, proto, _csum, src, dst = _IPV4.unpack_from(data, off)
            if ver_ihl >> 4 != 4:
                st.malformed += 1
                return None
            ihl = (ver_ihl & 0x0F) * 4
            if total_len == 0:
                # TCP segmentation offload on the capturing host leaves the field 0.
                total_len = len(data) - off
            if ihl < 20 or total_len < ihl:
                st.malformed += 1
                return None
            frag_offset = frag & 0x1FFF
            is_fragment = bool(frag & 0x2000) or frag_offset > 0
            ip_version, ip_len, ip_hdr = 4, total_len, ihl
            src_ip, dst_ip = socket.inet_ntoa(src), socket.inet_ntoa(dst)
            l4_off = off + ihl
            l4_room = total_len - ihl                       # bytes after the IP header
            l4_present = frag_offset == 0
        elif ethertype == ETH_IPV6:
            if len(data) < off + 40:
                st.malformed += 1
                return None
            vtf, plen, proto, ttl, src, dst = _IPV6.unpack_from(data, off)
            if vtf >> 28 != 6:
                st.malformed += 1
                return None
            ip_version, ip_len = 6, 40 + plen
            src_ip, dst_ip = socket.inet_ntop(socket.AF_INET6, src), socket.inet_ntop(socket.AF_INET6, dst)
            l4_off = off + 40
            is_fragment, l4_present = False, True
            while proto in IPV6_EXT_HEADERS or proto == IPV6_FRAGMENT:
                if len(data) < l4_off + 8:
                    break
                nxt = data[l4_off]
                if proto == IPV6_FRAGMENT:
                    frag_field = _U16.unpack_from(data, l4_off + 2)[0]
                    is_fragment = True
                    l4_present = (frag_field >> 3) == 0
                    ext_len = 8
                else:
                    ext_len = (data[l4_off + 1] + 1) * 8
                proto = nxt
                l4_off += ext_len
            ip_hdr = l4_off - off
            l4_room = ip_len - ip_hdr
        else:
            st.non_ip += 1
            return None

        src_port = dst_port = 0
        l4_hdr = 0
        tcp_flags = 0
        tcp_window = icmp_type = icmp_code = -1
        truncated = False

        if l4_present:
            if proto == PROTO_TCP:
                if len(data) >= l4_off + 20:
                    src_port, dst_port, _seq, _ack, doff, flags, tcp_window = _TCP.unpack_from(data, l4_off)
                    l4_hdr = (doff >> 4) * 4
                    tcp_flags = ((doff & 0x01) << 8) | flags
                else:
                    truncated = True
            elif proto == PROTO_UDP:
                if len(data) >= l4_off + 8:
                    src_port, dst_port, _ulen, _ucsum = _UDP.unpack_from(data, l4_off)
                    l4_hdr = 8
                else:
                    truncated = True
            elif proto in (PROTO_ICMP, PROTO_ICMPV6):
                if len(data) >= l4_off + 4:
                    icmp_type, icmp_code = data[l4_off], data[l4_off + 1]
                    l4_hdr = 8 if l4_room >= 8 else 4
                else:
                    truncated = True

        # A truncated L4 header has unknown length; assume the minimum for the protocol.
        min_hdr = {PROTO_TCP: 20, PROTO_UDP: 8, PROTO_ICMP: 8, PROTO_ICMPV6: 8}.get(proto, 0)
        payload_len = max(l4_room - (min_hdr if truncated else l4_hdr), 0)
        rec = PacketRecord(
            ts_ns, ip_version, src_ip, dst_ip, src_port, dst_port, proto,
            frame_len, ip_len, ip_hdr, l4_hdr, payload_len, ttl,
            tcp_flags, tcp_window, icmp_type, icmp_code, is_fragment, truncated,
        )
        st.count(rec)
        return rec
    except (struct.error, IndexError, ValueError, OSError):
        st.malformed += 1
        return None


def iter_packets(frames: Iterable[RawFrame], stats: ParseStats | None = None) -> Iterable[PacketRecord]:
    """Decode a stream of frames, skipping those that are not valid IP packets."""
    st = stats if stats is not None else ParseStats()
    for fr in frames:
        rec = parse_frame(fr.data, fr.linktype, fr.ts_ns, fr.wirelen, st)
        if rec is not None:
            yield rec


def records_to_table(records: list[PacketRecord]) -> pa.Table:
    """Convert decoded records to an Arrow table with :data:`PACKET_SCHEMA`."""
    cols = list(zip(*records)) if records else [[] for _ in PacketRecord._fields]
    data: dict[str, Any] = dict(zip(PacketRecord._fields, cols))
    data["timestamp"] = data["ts_ns"]
    arrays = [pa.array(data[f.name], type=pa.int64() if f.name == "timestamp" else f.type)
              for f in PACKET_SCHEMA]
    arrays[1] = arrays[1].cast(PACKET_SCHEMA.field("timestamp").type)
    return pa.Table.from_arrays(arrays, schema=PACKET_SCHEMA)


@dataclass
class ExtractionSummary:
    """Result of :func:`extract_packets`, also written next to the outputs as JSON."""

    pcap: str
    capture_format: str
    outputs: dict[str, str]
    read: dict[str, Any]
    parse: dict[str, Any]
    seconds: float
    packets_per_second: float
    first_ts_utc: str | None
    last_ts_utc: str | None


def _ts_iso(ts_ns: int | None) -> str | None:
    if ts_ns is None:
        return None
    sec, ns = divmod(ts_ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + f".{ns:09d}Z"


def extract_packets(
    pcap_path: str | Path,
    out_dir: str | Path,
    cfg: dict[str, Any],
    max_packets: int | None = None,
    formats: Iterable[str] | None = None,
) -> ExtractionSummary:
    """Extract packet fields from a capture and write them in chunks.

    Args:
        pcap_path: Input capture (pcap or pcapng).
        out_dir: Output directory; files are named after the capture.
        cfg: Loaded configuration (``pcap`` and ``storage`` sections).
        max_packets: Read at most this many frames.
        formats: Subset of ``{"parquet", "csv"}``; default from config.

    Returns:
        Extraction summary with read/parse counters and throughput.

    Raises:
        InsufficientStorageError: If the estimated output does not fit on disk.
        ValueError: If an unknown output format is requested.
    """
    pcap_path = Path(pcap_path)
    out_dir = Path(out_dir)
    pcfg = cfg.get("pcap", {})
    fmts = list(formats or pcfg.get("export_formats", ["parquet"]))
    unknown = set(fmts) - {"parquet", "csv"}
    if unknown:
        raise ValueError(f"Unknown output formats: {sorted(unknown)}")
    chunk_rows = int(pcfg.get("chunk_rows", 500_000))

    fmt = capture_format(pcap_path)
    size = pcap_path.stat().st_size
    bytes_per_pkt = float(pcfg.get("estimated_output_bytes_per_packet", 150)) * len(fmts)
    avg_frame = float(pcfg.get("estimated_capture_bytes_per_packet", 600))
    est_packets = min(size / avg_frame, max_packets) if max_packets else size / avg_frame
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_free_space(out_dir, cfg, required_gb=est_packets * bytes_per_pkt / 1024**3)

    stem = pcap_path.stem + (f".first{max_packets}" if max_packets else "")
    outputs = {f: str(out_dir / f"{stem}.packets.{f}") for f in fmts}
    rstats, pstats = ReadStats(), ParseStats()
    pq_writer: pq.ParquetWriter | None = None
    csv_writer: pa_csv.CSVWriter | None = None
    t0 = time.perf_counter()
    logger.info("Extracting packets from %s (%s, %.2f GB)%s", pcap_path.name, fmt, size / 1e9,
                f", first {max_packets:,} frames" if max_packets else "")
    try:
        if "parquet" in fmts:
            pq_writer = pq.ParquetWriter(outputs["parquet"], PACKET_SCHEMA, compression="zstd")
        if "csv" in fmts:
            csv_writer = pa_csv.CSVWriter(outputs["csv"], PACKET_SCHEMA)
        buf: list[PacketRecord] = []
        for rec in iter_packets(iter_raw_frames(pcap_path, max_packets, rstats), pstats):
            buf.append(rec)
            if len(buf) >= chunk_rows:
                _write_chunk(buf, pq_writer, csv_writer)
                logger.info("  %s frames read, %s packets written", f"{rstats.frames:,}", f"{pstats.parsed:,}")
                buf = []
        if buf:
            _write_chunk(buf, pq_writer, csv_writer)
    finally:
        if pq_writer is not None:
            pq_writer.close()
        if csv_writer is not None:
            csv_writer.close()

    elapsed = time.perf_counter() - t0
    summary = ExtractionSummary(
        pcap=str(pcap_path), capture_format=fmt, outputs=outputs,
        read=asdict(rstats), parse=asdict(pstats), seconds=round(elapsed, 3),
        packets_per_second=round(rstats.frames / elapsed, 1) if elapsed > 0 else 0.0,
        first_ts_utc=_ts_iso(rstats.first_ts_ns), last_ts_utc=_ts_iso(rstats.last_ts_ns),
    )
    summary_path = out_dir / f"{stem}.packets.summary.json"
    summary_path.write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")
    if rstats.read_error:
        logger.error("Capture read stopped early: %s", rstats.read_error)
    logger.info("Done: %s frames, %s IP packets, %s non-IP, %s malformed in %.1fs (%.0f frames/s)",
                f"{rstats.frames:,}", f"{pstats.parsed:,}", f"{pstats.non_ip:,}", f"{pstats.malformed:,}",
                elapsed, summary.packets_per_second)
    return summary


def _write_chunk(buf: list[PacketRecord], pq_writer: pq.ParquetWriter | None,
                 csv_writer: pa_csv.CSVWriter | None) -> None:
    table = records_to_table(buf)
    if pq_writer is not None:
        pq_writer.write_table(table)
    if csv_writer is not None:
        csv_writer.write_table(table)


def main(argv: list[str] | None = None) -> int:
    """CLI wrapper around :func:`extract_packets`."""
    from utils.config import get_path, load_config
    from utils.logging_setup import setup_logging

    parser = argparse.ArgumentParser(description="Extract packet header fields from a capture")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--out-dir", default=None, help="Default: <processed_dir>/packets")
    parser.add_argument("--max-packets", type=int, default=None)
    parser.add_argument("--formats", nargs="+", choices=["parquet", "csv"], default=None)
    parser.add_argument("--config", default=None)
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    setup_logging(cfg)
    out_dir = Path(args.out_dir) if args.out_dir else get_path(cfg, "processed_dir") / "packets"
    summary = extract_packets(args.pcap, out_dir, cfg, args.max_packets, args.formats)
    return 1 if summary.read["read_error"] else 0


if __name__ == "__main__":
    sys.exit(main())
