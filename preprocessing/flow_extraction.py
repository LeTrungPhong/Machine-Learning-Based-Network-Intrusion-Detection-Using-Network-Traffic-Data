"""Bidirectional flow reconstruction and flow-level feature computation.

Packets are grouped by 5-tuple regardless of direction. The host that sent
the first packet of a flow is the *forward* (source) side, as in
CICFlowMeter. Flows end on:

* ``fin``            - FIN seen from both sides (plus a short grace period)
* ``rst``            - TCP reset (plus grace period)
* ``flow_timeout``   - packet arrives more than ``flow_timeout_s`` after the flow start
* ``idle_timeout``   - no packet for ``idle_timeout_s``
* ``end_of_capture`` - still open when input ends (``incomplete = True``)
* ``evicted``        - dropped to respect ``max_active_flows`` (``incomplete = True``)

Statistics are updated incrementally (Welford), so memory per flow is
constant and the same :class:`FlowManager` is used for live capture.
Durations and inter-arrival times are in microseconds and packet lengths are
transport payload bytes, matching CICFlowMeter units. Standard deviations
use the sample (n-1) estimator, as CICFlowMeter does.

Usage:
    python -m preprocessing.flow_extraction --pcap <file> [--max-packets N]
    python -m preprocessing.flow_extraction --packets <packets.parquet>
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

import pandas as pd
import pyarrow as pa
import pyarrow.csv as pa_csv
import pyarrow.parquet as pq

from preprocessing.extract_packets import (
    ACK, CWR, ECE, FIN, PSH, RST, SYN, URG, PROTO_TCP, PacketRecord, ParseStats, iter_packets,
)
from preprocessing.read_pcap import ReadStats, iter_raw_frames
from utils.storage import ensure_free_space

logger = logging.getLogger(__name__)

US = 1_000  # nanoseconds per microsecond


class RunningStats:
    """Incremental count / mean / sample std / min / max (Welford's algorithm)."""

    __slots__ = ("n", "mean", "m2", "min", "max", "total")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min = math.inf
        self.max = -math.inf
        self.total = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        self.total += x
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)
        if x < self.min:
            self.min = x
        if x > self.max:
            self.max = x

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    def summary(self) -> tuple[float, float, float, float]:
        """Return ``(mean, std, max, min)``; zeros when empty (CICFlowMeter convention)."""
        if self.n == 0:
            return 0.0, 0.0, 0.0, 0.0
        return self.mean, self.std, self.max, self.min


@dataclass(frozen=True)
class FlowConfig:
    """Flow reconstruction parameters (see ``flow`` section of config.yaml)."""

    flow_timeout_s: float = 120.0
    idle_timeout_s: float = 120.0
    activity_timeout_s: float = 5.0
    tcp_close_grace_s: float = 1.0
    dedup_window_us: int = 0
    reorder_window_us: int = 1000
    sweep_interval_s: float = 1.0
    max_active_flows: int = 500_000

    @classmethod
    def from_cfg(cls, cfg: dict[str, Any]) -> "FlowConfig":
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in cfg.get("flow", {}).items() if k in known})


FLAG_ORDER: tuple[tuple[str, int], ...] = (
    ("fin", FIN), ("syn", SYN), ("rst", RST), ("psh", PSH),
    ("ack", ACK), ("urg", URG), ("ece", ECE), ("cwr", CWR),
)


class _Flow:
    """Mutable state of one open flow."""

    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start", "last", "last_fwd", "last_bwd",
        "fwd_len", "bwd_len", "all_len", "flow_iat", "fwd_iat", "bwd_iat",
        "flags", "fwd_psh", "bwd_psh", "fwd_urg", "bwd_urg",
        "fwd_hdr", "bwd_hdr", "init_win_fwd", "init_win_bwd",
        "act_data_fwd", "min_seg_fwd", "active", "idle", "active_start", "active_end",
        "fin_fwd", "fin_bwd", "closing_since", "close_reason", "dup_dropped", "last_sig",
        "out_of_order", "first_pkt",
    )

    def __init__(self, p: PacketRecord) -> None:
        self.src_ip, self.dst_ip = p.src_ip, p.dst_ip
        self.src_port, self.dst_port, self.protocol = p.src_port, p.dst_port, p.protocol
        self.start = self.last = self.active_start = self.active_end = p.ts_ns
        self.last_fwd = self.last_bwd = -1
        self.fwd_len, self.bwd_len, self.all_len = RunningStats(), RunningStats(), RunningStats()
        self.flow_iat, self.fwd_iat, self.bwd_iat = RunningStats(), RunningStats(), RunningStats()
        self.active, self.idle = RunningStats(), RunningStats()
        self.flags = [0] * len(FLAG_ORDER)
        self.fwd_psh = self.bwd_psh = self.fwd_urg = self.bwd_urg = 0
        self.fwd_hdr = self.bwd_hdr = 0
        self.init_win_fwd = self.init_win_bwd = -1
        self.act_data_fwd = 0
        self.min_seg_fwd = -1
        self.fin_fwd = self.fin_bwd = False
        self.closing_since: int | None = None
        self.close_reason = ""
        self.dup_dropped = 0
        self.last_sig: tuple | None = None
        self.out_of_order = 0
        self.first_pkt = p

    def add(self, p: PacketRecord, fwd: bool, activity_ns: int) -> None:
        ts = p.ts_ns
        if ts < self.last:
            self.out_of_order += 1
        if self.all_len.n > 0:
            self.flow_iat.add(max(ts - self.last, 0) / US)
        # Active / idle periods (CICFlowMeter updateActiveIdleTime)
        if ts - self.active_end > activity_ns:
            if self.active_end - self.active_start > 0:
                self.active.add((self.active_end - self.active_start) / US)
            self.idle.add((ts - self.active_end) / US)
            self.active_start = self.active_end = ts
        elif ts > self.active_end:
            self.active_end = ts

        size = p.payload_len
        self.all_len.add(size)
        flags = p.tcp_flags
        if fwd:
            self.fwd_len.add(size)
            if self.last_fwd >= 0:
                self.fwd_iat.add(max(ts - self.last_fwd, 0) / US)
            self.last_fwd = max(ts, self.last_fwd)
            self.fwd_hdr += p.l4_header_len
            if self.init_win_fwd < 0 and p.tcp_window >= 0:
                self.init_win_fwd = p.tcp_window
            if size > 0:
                self.act_data_fwd += 1
            if self.min_seg_fwd < 0 or p.l4_header_len < self.min_seg_fwd:
                self.min_seg_fwd = p.l4_header_len
            if flags & PSH:
                self.fwd_psh += 1
            if flags & URG:
                self.fwd_urg += 1
            if flags & FIN:
                self.fin_fwd = True
        else:
            self.bwd_len.add(size)
            if self.last_bwd >= 0:
                self.bwd_iat.add(max(ts - self.last_bwd, 0) / US)
            self.last_bwd = max(ts, self.last_bwd)
            self.bwd_hdr += p.l4_header_len
            if self.init_win_bwd < 0 and p.tcp_window >= 0:
                self.init_win_bwd = p.tcp_window
            if flags & PSH:
                self.bwd_psh += 1
            if flags & URG:
                self.bwd_urg += 1
            if flags & FIN:
                self.fin_bwd = True
        if flags:
            for i, (_, bit) in enumerate(FLAG_ORDER):
                if flags & bit:
                    self.flags[i] += 1
        self.last = max(ts, self.last)

    def finalize(self, reason: str) -> dict[str, Any]:
        """Close the flow and return its feature row."""
        if self.active_end - self.active_start > 0:
            self.active.add((self.active_end - self.active_start) / US)
        duration_us = (self.last - self.start) / US
        dur_s = duration_us / 1e6
        fwd_n, bwd_n = self.fwd_len.n, self.bwd_len.n
        n = fwd_n + bwd_n
        fwd_bytes, bwd_bytes = int(self.fwd_len.total), int(self.bwd_len.total)
        fl_mean, fl_std, fl_max, fl_min = self.fwd_len.summary()
        bl_mean, bl_std, bl_max, bl_min = self.bwd_len.summary()
        al_mean, al_std, al_max, al_min = self.all_len.summary()
        fi_mean, fi_std, fi_max, fi_min = self.flow_iat.summary()
        ffi_mean, ffi_std, ffi_max, ffi_min = self.fwd_iat.summary()
        bfi_mean, bfi_std, bfi_max, bfi_min = self.bwd_iat.summary()
        ac_mean, ac_std, ac_max, ac_min = self.active.summary()
        id_mean, id_std, id_max, id_min = self.idle.summary()
        row: dict[str, Any] = {
            "flow_id": f"{self.src_ip}-{self.dst_ip}-{self.src_port}-{self.dst_port}-{self.protocol}",
            "src_ip": self.src_ip, "src_port": self.src_port,
            "dst_ip": self.dst_ip, "dst_port": self.dst_port, "protocol": self.protocol,
            "start_ts_ns": self.start, "end_ts_ns": self.last,
            "termination": reason,
            "incomplete": reason in ("end_of_capture", "evicted"),
            "flow_duration_us": duration_us,
            "fwd_pkts": fwd_n, "bwd_pkts": bwd_n,
            "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
            "fwd_pkt_len_max": fl_max, "fwd_pkt_len_min": fl_min,
            "fwd_pkt_len_mean": fl_mean, "fwd_pkt_len_std": fl_std,
            "bwd_pkt_len_max": bl_max, "bwd_pkt_len_min": bl_min,
            "bwd_pkt_len_mean": bl_mean, "bwd_pkt_len_std": bl_std,
            "flow_bytes_per_s": (fwd_bytes + bwd_bytes) / dur_s if dur_s > 0 else 0.0,
            "flow_pkts_per_s": n / dur_s if dur_s > 0 else 0.0,
            "flow_iat_mean": fi_mean, "flow_iat_std": fi_std, "flow_iat_max": fi_max, "flow_iat_min": fi_min,
            "fwd_iat_total": self.fwd_iat.total, "fwd_iat_mean": ffi_mean, "fwd_iat_std": ffi_std,
            "fwd_iat_max": ffi_max, "fwd_iat_min": ffi_min,
            "bwd_iat_total": self.bwd_iat.total, "bwd_iat_mean": bfi_mean, "bwd_iat_std": bfi_std,
            "bwd_iat_max": bfi_max, "bwd_iat_min": bfi_min,
            "fwd_psh_flags": self.fwd_psh, "bwd_psh_flags": self.bwd_psh,
            "fwd_urg_flags": self.fwd_urg, "bwd_urg_flags": self.bwd_urg,
            "fwd_header_len": self.fwd_hdr, "bwd_header_len": self.bwd_hdr,
            "fwd_pkts_per_s": fwd_n / dur_s if dur_s > 0 else 0.0,
            "bwd_pkts_per_s": bwd_n / dur_s if dur_s > 0 else 0.0,
            "pkt_len_min": al_min, "pkt_len_max": al_max, "pkt_len_mean": al_mean,
            "pkt_len_std": al_std, "pkt_len_var": al_std ** 2,
        }
        for (name, _), cnt in zip(FLAG_ORDER, self.flags):
            row[f"{name}_flag_cnt"] = cnt
        row.update({
            "down_up_ratio": bwd_n / fwd_n if fwd_n else 0.0,
            "avg_pkt_size": (fwd_bytes + bwd_bytes) / n if n else 0.0,
            "init_win_bytes_fwd": self.init_win_fwd, "init_win_bytes_bwd": self.init_win_bwd,
            "act_data_pkt_fwd": self.act_data_fwd,
            "min_seg_size_fwd": max(self.min_seg_fwd, 0),
            "active_mean": ac_mean, "active_std": ac_std, "active_max": ac_max, "active_min": ac_min,
            "idle_mean": id_mean, "idle_std": id_std, "idle_max": id_max, "idle_min": id_min,
            "dup_pkts_dropped": self.dup_dropped,
            "out_of_order_pkts": self.out_of_order,
        })
        return row


#: Our column -> CIC-IDS-2017 CSV column (after stripping spaces), for features
#: computed with the same definition. Used to compare against the published CSVs.
CIC_COLUMN_MAP: dict[str, str] = {
    "flow_duration_us": "Flow Duration", "fwd_pkts": "Total Fwd Packets", "bwd_pkts": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets", "bwd_bytes": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max", "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean", "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max", "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean", "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_bytes_per_s": "Flow Bytes/s", "flow_pkts_per_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean", "flow_iat_std": "Flow IAT Std", "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min", "fwd_iat_total": "Fwd IAT Total", "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std", "fwd_iat_max": "Fwd IAT Max", "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_total": "Bwd IAT Total", "bwd_iat_mean": "Bwd IAT Mean", "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max", "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags", "fwd_urg_flags": "Fwd URG Flags",
    "fwd_pkts_per_s": "Fwd Packets/s", "bwd_pkts_per_s": "Bwd Packets/s",
    "fin_flag_cnt": "FIN Flag Count", "syn_flag_cnt": "SYN Flag Count", "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count", "ack_flag_cnt": "ACK Flag Count", "urg_flag_cnt": "URG Flag Count",
    "ece_flag_cnt": "ECE Flag Count", "down_up_ratio": "Down/Up Ratio",
    "init_win_bytes_fwd": "Init_Win_bytes_forward", "init_win_bytes_bwd": "Init_Win_bytes_backward",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "active_mean": "Active Mean", "active_std": "Active Std", "active_max": "Active Max", "active_min": "Active Min",
    "idle_mean": "Idle Mean", "idle_std": "Idle Std", "idle_max": "Idle Max", "idle_min": "Idle Min",
}


@dataclass
class FlowStats:
    """Counters reported by :class:`FlowManager`."""

    packets: int = 0
    flows_emitted: int = 0
    duplicates_dropped: int = 0
    reordered_handshakes: int = 0
    max_active: int = 0
    terminations: dict[str, int] = field(default_factory=dict)


class FlowManager:
    """Assemble packets into bidirectional flows and emit finished flow rows.

    Feed packets in capture order with :meth:`process`; finished flows are
    returned as dictionaries. Call :meth:`flush` at the end of input.
    """

    def __init__(self, fc: FlowConfig | None = None) -> None:
        self.fc = fc or FlowConfig()
        self._flow_ns = int(self.fc.flow_timeout_s * 1e9)
        self._idle_ns = int(self.fc.idle_timeout_s * 1e9)
        self._activity_ns = int(self.fc.activity_timeout_s * 1e9)
        self._grace_ns = int(self.fc.tcp_close_grace_s * 1e9)
        self._dedup_ns = int(self.fc.dedup_window_us) * US
        self._reorder_ns = int(self.fc.reorder_window_us) * US
        self._sweep_ns = int(self.fc.sweep_interval_s * 1e9)
        self.flows: dict[tuple, _Flow] = {}
        self.clock = 0
        self._last_sweep = 0
        self.stats = FlowStats()

    @staticmethod
    def _key(p: PacketRecord) -> tuple:
        a, b = (p.src_ip, p.src_port), (p.dst_ip, p.dst_port)
        return (a, b, p.protocol) if a <= b else (b, a, p.protocol)

    def _emit(self, key: tuple, reason: str, out: list[dict[str, Any]]) -> None:
        f = self.flows.pop(key)
        out.append(f.finalize(f.close_reason or reason))
        r = f.close_reason or reason
        self.stats.terminations[r] = self.stats.terminations.get(r, 0) + 1
        self.stats.flows_emitted += 1

    def process(self, p: PacketRecord) -> list[dict[str, Any]]:
        """Add one packet; return the flows that finished as a result."""
        out: list[dict[str, Any]] = []
        self.stats.packets += 1
        now = p.ts_ns
        if now > self.clock:
            self.clock = now
        if self.clock - self._last_sweep >= self._sweep_ns:
            out.extend(self.sweep(self.clock))

        key = self._key(p)
        f = self.flows.get(key)
        is_tcp = p.protocol == PROTO_TCP
        new_syn = is_tcp and (p.tcp_flags & SYN) and not (p.tcp_flags & ACK)
        if f is not None and new_syn and self._is_reordered_reply(f, p):
            # Rebuild with the SYN sender as initiator, then replay the early reply.
            reply = f.first_pkt
            f = _Flow(p)
            self.flows[key] = f
            f.add(p, True, self._activity_ns)
            f.add(reply, False, self._activity_ns)
            if reply.tcp_flags & RST:
                f.closing_since, f.close_reason = now, "rst"
            self.stats.reordered_handshakes += 1
            return out
        if f is not None:
            if f.closing_since is not None:
                if new_syn or now - f.closing_since > self._grace_ns:
                    self._emit(key, f.close_reason, out)
                    f = None
            elif now - f.start > self._flow_ns:
                self._emit(key, "flow_timeout", out)
                f = None
            elif now - f.last > self._idle_ns:
                self._emit(key, "idle_timeout", out)
                f = None

        if f is None:
            f = _Flow(p)
            self.flows[key] = f
            if len(self.flows) > self.stats.max_active:
                self.stats.max_active = len(self.flows)
            if len(self.flows) > self.fc.max_active_flows:
                self._evict_oldest(out)

        fwd = p.src_ip == f.src_ip and p.src_port == f.src_port
        if self._dedup_ns:
            sig = (fwd, p.ip_len, p.tcp_flags, p.payload_len, p.ttl)
            if sig == f.last_sig and 0 <= now - f.last <= self._dedup_ns:
                f.dup_dropped += 1
                self.stats.duplicates_dropped += 1
                return out
            f.last_sig = sig

        f.add(p, fwd, self._activity_ns)
        if is_tcp and f.closing_since is None:
            if p.tcp_flags & RST:
                f.closing_since, f.close_reason = now, "rst"
            elif f.fin_fwd and f.fin_bwd:
                f.closing_since, f.close_reason = now, "fin"
        return out

    def _is_reordered_reply(self, f: _Flow, syn: PacketRecord) -> bool:
        """True if ``f`` holds only a reply to ``syn`` that was timestamped before it."""
        if self._reorder_ns <= 0 or f.all_len.n != 1:
            return False
        first = f.first_pkt
        is_reply = bool(first.tcp_flags & (ACK | RST)) and first.src_ip == syn.dst_ip and first.src_port == syn.dst_port
        return is_reply and 0 <= syn.ts_ns - first.ts_ns <= self._reorder_ns

    def sweep(self, now: int) -> list[dict[str, Any]]:
        """Emit flows that are closed, idle or past the flow timeout at time ``now``."""
        self._last_sweep = now
        out: list[dict[str, Any]] = []
        expired = []
        for key, f in self.flows.items():
            if f.closing_since is not None:
                if now - f.closing_since > self._grace_ns:
                    expired.append((key, f.close_reason))
            elif now - f.last > self._idle_ns:
                expired.append((key, "idle_timeout"))
            elif now - f.start > self._flow_ns:
                expired.append((key, "flow_timeout"))
        for key, reason in expired:
            self._emit(key, reason, out)
        return out

    def _evict_oldest(self, out: list[dict[str, Any]]) -> None:
        n = max(1, len(self.flows) - self.fc.max_active_flows)
        oldest = sorted(self.flows.items(), key=lambda kv: kv[1].last)[:n]
        for key, f in oldest:
            f.close_reason = ""
            self._emit(key, "evicted", out)

    def flush(self) -> list[dict[str, Any]]:
        """Emit all remaining flows (end of input)."""
        out: list[dict[str, Any]] = []
        for key in list(self.flows):
            f = self.flows[key]
            # A TCP flow already closed by FIN/RST is complete, not truncated by the capture end.
            self._emit(key, f.close_reason if f.closing_since is not None else "end_of_capture", out)
        return out


def iter_flows(packets: Iterable[PacketRecord], fc: FlowConfig | None = None,
               manager: FlowManager | None = None) -> Iterator[dict[str, Any]]:
    """Yield finished flow rows from a packet stream (flushes at the end)."""
    fm = manager or FlowManager(fc)
    for p in packets:
        yield from fm.process(p)
    yield from fm.flush()


def iter_packets_from_parquet(path: str | Path, batch_rows: int = 200_000) -> Iterator[PacketRecord]:
    """Read packets written by :mod:`preprocessing.extract_packets` back as records."""
    pf = pq.ParquetFile(path)
    cols = list(PacketRecord._fields)
    for batch in pf.iter_batches(batch_size=batch_rows, columns=cols):
        data = batch.to_pydict()
        for row in zip(*(data[c] for c in cols)):
            yield PacketRecord(*row)


def flows_to_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert flow rows to a DataFrame with a UTC ``timestamp`` column (flow start)."""
    df = pd.DataFrame.from_records(rows)
    if not df.empty:
        df.insert(df.columns.get_loc("start_ts_ns"), "timestamp",
                  pd.to_datetime(df["start_ts_ns"], unit="ns", utc=True))
    return df


@dataclass
class FlowExtractionSummary:
    """Written as ``<name>.flows.summary.json`` next to the outputs."""

    source: str
    outputs: dict[str, str]
    flow_config: dict[str, Any]
    read: dict[str, Any] | None
    parse: dict[str, Any] | None
    flows: dict[str, Any]
    seconds: float
    packets_per_second: float


def extract_flows(
    out_dir: str | Path,
    cfg: dict[str, Any],
    pcap: str | Path | None = None,
    packets_parquet: str | Path | None = None,
    max_packets: int | None = None,
    formats: Iterable[str] | None = None,
    name: str | None = None,
) -> FlowExtractionSummary:
    """Reconstruct flows from a capture or a packets Parquet file and export them.

    Exactly one of ``pcap`` / ``packets_parquet`` must be given.

    Raises:
        ValueError: On invalid arguments.
        InsufficientStorageError: If the output may not fit on disk.
    """
    if (pcap is None) == (packets_parquet is None):
        raise ValueError("Give exactly one of pcap or packets_parquet")
    fcfg = cfg.get("flow", {})
    fmts = list(formats or fcfg.get("export_formats", ["parquet", "csv"]))
    if set(fmts) - {"parquet", "csv"}:
        raise ValueError(f"Unknown output formats: {fmts}")
    chunk_rows = int(fcfg.get("chunk_rows", 200_000))
    fc = FlowConfig.from_cfg(cfg)
    src = Path(pcap or packets_parquet)  # type: ignore[arg-type]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Flow rows are ~1 KB in CSV; a flow averages >= 10 packets of >= 60 bytes in typical traces.
    ensure_free_space(out_dir, cfg, required_gb=src.stat().st_size / 600 * 1024 * len(fmts) / 1024**3 / 10)

    stem = name or (src.name.split(".packets.")[0] if packets_parquet else src.stem)
    if max_packets and not name:
        stem += f".first{max_packets}"
    outputs = {f: str(out_dir / f"{stem}.flows.{f}") for f in fmts}

    rstats: ReadStats | None = None
    pstats: ParseStats | None = None
    if pcap is not None:
        rstats, pstats = ReadStats(), ParseStats()
        packets: Iterable[PacketRecord] = iter_packets(iter_raw_frames(pcap, max_packets, rstats), pstats)
    else:
        packets = iter_packets_from_parquet(packets_parquet)  # type: ignore[arg-type]
        if max_packets:
            from itertools import islice
            packets = islice(packets, max_packets)

    fm = FlowManager(fc)
    pq_writer: pq.ParquetWriter | None = None
    csv_writer: pa_csv.CSVWriter | None = None
    schema: pa.Schema | None = None
    t0 = time.perf_counter()
    logger.info("Building flows from %s", src.name)

    def write(rows: list[dict[str, Any]]) -> None:
        nonlocal pq_writer, csv_writer, schema
        table = pa.Table.from_pandas(flows_to_frame(rows), preserve_index=False)
        if schema is None:
            schema = table.schema
            if "parquet" in fmts:
                pq_writer = pq.ParquetWriter(outputs["parquet"], schema, compression="zstd")
            if "csv" in fmts:
                csv_writer = pa_csv.CSVWriter(outputs["csv"], schema)
        table = table.cast(schema)
        if pq_writer is not None:
            pq_writer.write_table(table)
        if csv_writer is not None:
            csv_writer.write_table(table)

    try:
        buf: list[dict[str, Any]] = []
        for row in iter_flows(packets, manager=fm):
            buf.append(row)
            if len(buf) >= chunk_rows:
                write(buf)
                logger.info("  %s packets, %s flows written, %s active",
                            f"{fm.stats.packets:,}", f"{fm.stats.flows_emitted:,}", f"{len(fm.flows):,}")
                buf = []
        if buf:
            write(buf)
    finally:
        if pq_writer is not None:
            pq_writer.close()
        if csv_writer is not None:
            csv_writer.close()

    elapsed = time.perf_counter() - t0
    summary = FlowExtractionSummary(
        source=str(src), outputs=outputs if schema is not None else {},
        flow_config=asdict(fc),
        read=asdict(rstats) if rstats else None, parse=asdict(pstats) if pstats else None,
        flows=asdict(fm.stats), seconds=round(elapsed, 3),
        packets_per_second=round(fm.stats.packets / elapsed, 1) if elapsed > 0 else 0.0,
    )
    (out_dir / f"{stem}.flows.summary.json").write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")
    if rstats is not None and rstats.read_error:
        logger.error("Capture read stopped early: %s", rstats.read_error)
    logger.info("Done: %s packets -> %s flows in %.1fs (%.0f packets/s); terminations %s",
                f"{fm.stats.packets:,}", f"{fm.stats.flows_emitted:,}", elapsed,
                summary.packets_per_second, fm.stats.terminations)
    return summary


def main(argv: list[str] | None = None) -> int:
    """CLI wrapper around :func:`extract_flows`."""
    from utils.config import get_path, load_config
    from utils.logging_setup import setup_logging

    ap = argparse.ArgumentParser(description="Reconstruct bidirectional flows")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap")
    src.add_argument("--packets", help="packets Parquet from extract_packets")
    ap.add_argument("--out-dir", default=None, help="Default: <processed_dir>/flows")
    ap.add_argument("--max-packets", type=int, default=None)
    ap.add_argument("--formats", nargs="+", choices=["parquet", "csv"], default=None)
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    setup_logging(cfg)
    out_dir = Path(args.out_dir) if args.out_dir else get_path(cfg, "processed_dir") / "flows"
    s = extract_flows(out_dir, cfg, pcap=args.pcap, packets_parquet=args.packets,
                      max_packets=args.max_packets, formats=args.formats)
    return 1 if s.read and s.read.get("read_error") else 0


if __name__ == "__main__":
    sys.exit(main())
