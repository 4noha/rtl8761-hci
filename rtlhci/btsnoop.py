"""btsnoop v1 capture writer (datalink 1002 = HCI UART / H4), readable by Wireshark and btmon.

File layout (all integers big-endian), per the btsnoop format used by Wireshark/BlueZ/Android:
  header : b"btsnoop\\0" | version u32 (=1) | datalink u32 (=1002)
  record : original_len u32 | included_len u32 | flags u32 | cumulative_drops u32 |
           timestamp i64 (microseconds since 0000-01-01 00:00 UTC) | packet bytes
  flags  : bit0 direction (0 = sent host->controller, 1 = received controller->host)
           bit1 0 = data (ACL/SCO/ISO), 1 = command or event
  H4 packet = type byte (01 cmd, 02 ACL, 03 SCO, 04 event, 05 ISO) + HCI packet.

The writer is hooked at exactly one place: the Transport tx/rx boundary
(`Transport._snoop`, called by UsbTransport and FakeTransport), so every complete HCI packet
is recorded once, after USB reassembly and before the HCI/L2CAP layers.
"""
from __future__ import annotations

import logging
import os
import struct
import threading
import time
from typing import Callable, Optional

log = logging.getLogger("rtlhci.btsnoop")

MAGIC = b"btsnoop\0"
VERSION = 1
DATALINK_H4 = 1002
EPOCH_DELTA_US = 0x00DCDDB30F2F8000  # 0000-01-01 -> 1970-01-01 in microseconds
HEADER = MAGIC + struct.pack(">II", VERSION, DATALINK_H4)
REC_HDR = struct.Struct(">IIIIq")

H4_CMD, H4_ACL, H4_SCO, H4_EVT, H4_ISO = 0x01, 0x02, 0x03, 0x04, 0x05

FLAG_RECEIVED = 0x01
FLAG_CMD_EVT = 0x02


def h4_flags(ptype: int, received: bool) -> int:
    f = FLAG_RECEIVED if received else 0
    if ptype in (H4_CMD, H4_EVT):
        f |= FLAG_CMD_EVT
    return f


def unix_to_btsnoop_us(t: float) -> int:
    return int(round(t * 1_000_000)) + EPOCH_DELTA_US


class BtSnoopWriter:
    """Append-only btsnoop writer with size rotation and a cumulative drops counter.

    path       : capture file. Rotation renames path -> path.1 -> path.2 ... (keeps `keep`).
    max_bytes  : rotate before a record would push the file past this size (None = never).
    flush_each : flush after every record (default) so a crash leaves a valid file; every
                 record goes out in a single write() so a file is never cut mid-record by us.
    snaplen    : truncate packets longer than this (included_len < original_len).
    clock      : returns UNIX seconds (injectable for reproducible test captures).
    A lock serialises record(); safe with the single-thread poller and with a reader thread.
    Write errors never propagate to the stack: the record is counted in `drops`.
    """

    def __init__(self, path: str, *, max_bytes: Optional[int] = None, keep: int = 3,
                 flush_each: bool = True, snaplen: int = 65535,
                 clock: Callable[[], float] = time.time):
        if max_bytes is not None and max_bytes < len(HEADER) + REC_HDR.size + 1:
            raise ValueError("max_bytes too small for one record")
        self.path, self.max_bytes, self.keep = path, max_bytes, max(1, keep)
        self.flush_each, self.snaplen, self.clock = flush_each, snaplen, clock
        self.drops = 0
        self.records = 0          # records in the current file
        self.total_records = 0    # records over all rotated files
        self.rotations = 0
        self._lock = threading.Lock()
        self._f = None
        self._size = 0
        self._open_new()

    # ------------------------------------------------------------- file handling
    def _open_new(self) -> None:
        f = open(self.path, "wb")
        f.write(HEADER)
        f.flush()
        self._f, self._size, self.records = f, len(HEADER), 0

    def _rotate(self) -> None:
        self._f.close()
        self._f = None
        for i in range(self.keep - 1, 0, -1):
            src = f"{self.path}.{i}"
            if os.path.exists(src):
                os.replace(src, f"{self.path}.{i + 1}")
        os.replace(self.path, f"{self.path}.1")
        stale = f"{self.path}.{self.keep + 1}"
        if os.path.exists(stale):
            os.remove(stale)
        self.rotations += 1
        self._open_new()

    # ------------------------------------------------------------- recording
    def record(self, ptype: int, pkt: bytes, received: bool, ts: Optional[float] = None) -> bool:
        """Record one HCI packet (without H4 byte; it is prepended here). Returns False if dropped."""
        data = bytes([ptype]) + bytes(pkt)
        inc = data[:self.snaplen]
        with self._lock:
            try:
                if self._f is None:
                    raise OSError("capture closed")
                us = unix_to_btsnoop_us(self.clock() if ts is None else ts)
                rec = REC_HDR.pack(len(data), len(inc), h4_flags(ptype, received), self.drops, us) + inc
                if (self.max_bytes is not None and self.records > 0
                        and self._size + len(rec) > self.max_bytes):
                    self._rotate()
                    rec = REC_HDR.pack(len(data), len(inc), h4_flags(ptype, received), self.drops, us) + inc
                self._f.write(rec)
                if self.flush_each:
                    self._f.flush()
                self._size += len(rec)
                self.records += 1
                self.total_records += 1
                return True
            except (OSError, ValueError) as exc:
                self.drops += 1
                if self.drops in (1, 10, 100) or self.drops % 1000 == 0:
                    log.warning("btsnoop: dropped record #%d (%s)", self.drops, exc)
                return False

    def flush(self) -> None:
        with self._lock:
            if self._f is not None:
                try:
                    self._f.flush()
                    os.fsync(self._f.fileno())
                except OSError as exc:
                    log.warning("btsnoop flush failed: %s", exc)

    def close(self) -> None:
        with self._lock:
            if self._f is not None:
                try:
                    self._f.flush()
                    os.fsync(self._f.fileno())
                finally:
                    self._f.close()
                    self._f = None

    def __enter__(self) -> "BtSnoopWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
