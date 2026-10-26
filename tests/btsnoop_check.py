#!/usr/bin/env python3
"""Independent btsnoop reader/validator (does not import rtlhci.btsnoop).

Checks: magic, version 1, datalink 1002, each record header sane, included<=original,
drops non-decreasing, timestamps after 2000-01-01 and non-decreasing, flag bit1 consistent
with the H4 type, and the HCI length fields inside each H4 packet match the record length.

  python tests/btsnoop_check.py capture.btsnoop      # prints a btmon-like summary
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass

Y2000_US = 0x00E03AB44A676000   # 2000-01-01 in btsnoop microseconds (sanity floor)
UNIX_DELTA_US = 0x00DCDDB30F2F8000


@dataclass
class Rec:
    orig: int
    incl: int
    flags: int
    drops: int
    ts: int
    data: bytes

    @property
    def received(self) -> bool:
        return bool(self.flags & 1)

    @property
    def unix_s(self) -> float:
        return (self.ts - UNIX_DELTA_US) / 1e6


class SnoopFormatError(ValueError):
    pass


def parse(blob: bytes) -> tuple[int, int, list[Rec]]:
    if len(blob) < 16 or blob[:8] != b"btsnoop\x00":
        raise SnoopFormatError("bad magic")
    ver, dlt = struct.unpack(">II", blob[8:16])
    off, recs = 16, []
    while off < len(blob):
        if off + 24 > len(blob):
            raise SnoopFormatError(f"truncated record header at {off}")
        orig, incl, flags, drops, ts = struct.unpack(">IIIIq", blob[off:off + 24])
        off += 24
        if incl > orig or off + incl > len(blob):
            raise SnoopFormatError(f"bad lengths orig={orig} incl={incl} at {off}")
        recs.append(Rec(orig, incl, flags, drops, ts, blob[off:off + incl]))
        off += incl
    return ver, dlt, recs


def validate(blob: bytes) -> list[Rec]:
    ver, dlt, recs = parse(blob)
    if ver != 1:
        raise SnoopFormatError(f"version {ver}")
    if dlt != 1002:
        raise SnoopFormatError(f"datalink {dlt}")
    last_ts, last_drops = 0, 0
    for i, r in enumerate(recs):
        if r.flags & ~3:
            raise SnoopFormatError(f"#{i}: reserved flag bits {r.flags:#x}")
        if r.ts < Y2000_US or r.ts < last_ts:
            raise SnoopFormatError(f"#{i}: timestamp {r.ts}")
        if r.drops < last_drops:
            raise SnoopFormatError(f"#{i}: drops decreased")
        last_ts, last_drops = r.ts, r.drops
        if not r.data:
            raise SnoopFormatError(f"#{i}: empty")
        t, p = r.data[0], r.data[1:]
        cmd_evt = bool(r.flags & 2)
        if t == 0x01:
            ok = cmd_evt and not r.received and len(p) >= 3 and p[2] == len(p) - 3
        elif t == 0x04:
            ok = cmd_evt and r.received and len(p) >= 2 and p[1] == len(p) - 2
        elif t == 0x02:
            ok = not cmd_evt and len(p) >= 4 and struct.unpack_from("<H", p, 2)[0] == len(p) - 4
        elif t in (0x03, 0x05):
            ok = not cmd_evt
        else:
            ok = False
        if r.incl == r.orig and not ok:
            raise SnoopFormatError(f"#{i}: inconsistent H4 packet {r.data.hex()}")
    return recs


def l2cap_frames(recs: list[Rec]) -> list[tuple[bool, int, int, bytes]]:
    """Reassemble ACL into (received, handle, cid, payload), per direction."""
    out, part = [], {}
    for r in recs:
        if r.data[0] != 0x02:
            continue
        hdr, ln = struct.unpack_from("<HH", r.data, 1)
        h, pb, data = hdr & 0xFFF, (hdr >> 12) & 3, r.data[5:5 + ln]
        key = (r.received, h)
        if pb != 0b01:
            part[key] = bytearray(data)
        elif key in part:
            part[key] += data
        else:
            continue
        b = part[key]
        if len(b) >= 4 and len(b) >= 4 + struct.unpack_from("<H", b)[0]:
            l, cid = struct.unpack_from("<HH", b)
            out.append((r.received, h, cid, bytes(b[4:4 + l])))
            del part[key]
    return out


def summary(path: str) -> str:
    recs = validate(open(path, "rb").read())
    lines = [f"{path}: {len(recs)} records, drops={recs[-1].drops if recs else 0}"]
    for r in recs:
        d = "<" if r.received else ">"
        kind = {1: "CMD", 2: "ACL", 3: "SCO", 4: "EVT", 5: "ISO"}.get(r.data[0], "?")
        lines.append(f"{r.unix_s:17.6f} {d} {kind} {r.data[1:].hex()}")
    return "\n".join(lines)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(summary(p))
