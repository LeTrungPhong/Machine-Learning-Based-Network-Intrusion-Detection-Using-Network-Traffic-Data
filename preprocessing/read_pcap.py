"""Streaming reader for pcap and pcapng captures.

Captures are read frame by frame with Scapy's raw readers, which auto-detect
pcap vs. pcapng from the magic number (CIC-IDS-2017 ships pcapng files with a
``.pcap`` extension). Frames are returned undecoded; header parsing happens in
:mod:`preprocessing.extract_packets` so that the offline and real-time paths
share one parser.

Timestamps are kept as exact integer nanoseconds since the Unix epoch.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, NamedTuple

try:
    from scapy.error import Scapy_Exception
    from scapy.utils import RawPcapNgReader, RawPcapReader
except ImportError:  # pragma: no cover
    class Scapy_Exception(Exception):  # type: ignore[no-redef]
        pass

    RawPcapNgReader = None  # type: ignore[assignment]
    RawPcapReader = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

NS_PER_S = 1_000_000_000


class RawFrame(NamedTuple):
    """One captured frame, not yet decoded."""

    ts_ns: int        # capture timestamp, integer nanoseconds since epoch (UTC)
    linktype: int     # DLT/LINKTYPE value of the interface (1 = Ethernet)
    data: bytes       # captured bytes (may be shorter than wirelen)
    wirelen: int      # original length on the wire


@dataclass
class ReadStats:
    """Counters collected while reading a capture."""

    frames: int = 0
    truncated: int = 0          # caplen < wirelen (snaplen cut)
    first_ts_ns: int | None = None
    last_ts_ns: int | None = None
    out_of_order: int = 0       # timestamp lower than the previous frame
    read_error: str | None = None
    linktypes: dict[int, int] = field(default_factory=dict)


def capture_format(path: str | Path) -> str:
    """Return ``"pcap"`` or ``"pcapng"`` from the magic number.

    Raises:
        ValueError: If the file is not a pcap/pcapng capture.
    """
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        return "pcap"
    raise ValueError(f"{path} is not a pcap/pcapng file (magic {magic.hex()})")


def _ng_ts_ns(tshigh: int, tslow: int, tsresol: int) -> int:
    """Convert a pcapng timestamp to integer nanoseconds without float rounding."""
    ticks = (tshigh << 32) | tslow
    if tsresol == NS_PER_S:
        return ticks
    if NS_PER_S % tsresol == 0:
        return ticks * (NS_PER_S // tsresol)
    return (ticks * NS_PER_S) // tsresol


def iter_raw_frames(
    path: str | Path,
    max_packets: int | None = None,
    stats: ReadStats | None = None,
) -> Iterator[RawFrame]:
    """Yield frames from a capture file without loading it into memory.

    Corrupted or truncated files do not raise: reading stops at the damaged
    record, the error is logged and stored in ``stats.read_error``.

    Args:
        path: pcap or pcapng file.
        max_packets: Stop after this many frames (``None`` = whole file).
        stats: Optional counters object updated in place.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the file is not a capture.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    capture_format(path)  # validates magic before Scapy opens it
    st = stats if stats is not None else ReadStats()

    try:
        reader = RawPcapReader(str(path))  # metaclass returns RawPcapNgReader for pcapng
    except Scapy_Exception as exc:
        raise ValueError(f"Cannot open {path}: {exc}") from exc

    is_ng = isinstance(reader, RawPcapNgReader)
    classic_linktype = getattr(reader, "linktype", 1)
    classic_mult = 1 if getattr(reader, "nano", False) else 1000
    prev_ts = -1
    try:
        while max_packets is None or st.frames < max_packets:
            try:
                data, meta = reader._read_packet()
            except EOFError:
                break
            except (Scapy_Exception, OSError, ValueError, OverflowError) as exc:
                st.read_error = f"{type(exc).__name__}: {exc}"
                logger.error("Stopped reading %s after %d frames: %s", path.name, st.frames, st.read_error)
                break

            if is_ng:
                ts_ns = _ng_ts_ns(meta.tshigh, meta.tslow, meta.tsresol)
                linktype = meta.linktype
                wirelen = meta.wirelen
            else:
                ts_ns = meta.sec * NS_PER_S + meta.usec * classic_mult
                linktype = classic_linktype
                wirelen = meta.wirelen

            st.frames += 1
            st.linktypes[linktype] = st.linktypes.get(linktype, 0) + 1
            if len(data) < wirelen:
                st.truncated += 1
            if ts_ns < prev_ts:
                st.out_of_order += 1
            prev_ts = ts_ns
            if st.first_ts_ns is None:
                st.first_ts_ns = ts_ns
            st.last_ts_ns = ts_ns
            yield RawFrame(ts_ns, linktype, data, wirelen)
    finally:
        reader.close()
