#!/usr/bin/env python3
"""Offline solver for the SMP confirm mismatch (read-only, no device access).

Takes a selftest log captured with SMP_DUMP=1 (which now dumps both directions)
and reports which f4 input combination reproduces Ca / Cb.

Usage:
    python smp_solve.py selftest-2026....log
    python smp_solve.py --peer-pub HEX --our-pub HEX --na HEX --nb HEX --ca HEX --cb HEX

Only public keys and pairing randoms are involved; nothing secret is printed.
"""
from __future__ import annotations

import argparse
import re
import sys

from rtlhci import smp_crypto as C

_TX = re.compile(r"smp pdu tx hex=([0-9a-f]+)")
_RX = re.compile(r"smp pdu hex=([0-9a-f]+)")


def parse_log(path: str) -> dict[str, list[bytes]]:
    out: dict[str, list[bytes]] = {"tx": [], "rx": []}
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = _TX.search(line)
            if m:
                out["tx"].append(bytes.fromhex(m.group(1)))
                continue
            m = _RX.search(line)
            if m:
                out["rx"].append(bytes.fromhex(m.group(1)))
    return out


def pick(pdus: list[bytes], code: int, size: int) -> bytes | None:
    found = [p[1:] for p in pdus if p and p[0] == code and len(p) == size + 1]
    return found[-1] if found else None


def xcross(own: bytes | None, peer: bytes | None, rnd: bytes | None):
    """Peer convention: f4(own_x, peer_x, rnd, z) -- X of both keys, no Y."""
    if not (own and peer and rnd) or len(own) != 64 or len(peer) != 64 or len(rnd) != 16:
        return
    for z in (0, 0x80):
        yield f"xcross z={z:#04x}", C.f4(own[:32], peer[:32], rnd, z)


def combos(pub: bytes | None, rnd: bytes | None):
    """Yield (label, f4 value) for every plausible interpretation."""
    if pub is None or len(pub) != 64 or rnd is None or len(rnd) != 16:
        return
    x, y = pub[:32], pub[32:]
    for order, (u, v) in {"XY": (x, y), "YX": (y, x)}.items():
        for z in (0, 0x80):
            yield f"{order} z={z:#04x}", C.f4(u, v, rnd, z)


def report(name: str, target: bytes | None, cands) -> bool:
    print(f"\n{name}: target={target.hex() if target else 'n/a'}")
    hit = False
    for label, val in cands:
        ok = target is not None and val == target
        hit |= ok
        print(f"  {label:12s} {val.hex()} {'  <== MATCH' if ok else ''}")
    return hit


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?")
    ap.add_argument("--our-pub")
    ap.add_argument("--peer-pub")
    ap.add_argument("--na")
    ap.add_argument("--nb")
    ap.add_argument("--ca")
    ap.add_argument("--cb")
    a = ap.parse_args()

    vals = {
        "our_pub": bytes.fromhex(a.our_pub) if a.our_pub else None,
        "peer_pub": bytes.fromhex(a.peer_pub) if a.peer_pub else None,
        "na": bytes.fromhex(a.na) if a.na else None,
        "nb": bytes.fromhex(a.nb) if a.nb else None,
        "ca": bytes.fromhex(a.ca) if a.ca else None,
        "cb": bytes.fromhex(a.cb) if a.cb else None,
    }
    if a.log:
        d = parse_log(a.log)
        vals["our_pub"] = vals["our_pub"] or pick(d["tx"], 0x0C, 64)
        vals["peer_pub"] = vals["peer_pub"] or pick(d["rx"], 0x0C, 64)
        vals["na"] = vals["na"] or pick(d["tx"], 0x04, 16)
        vals["nb"] = vals["nb"] or pick(d["rx"], 0x04, 16)
        vals["ca"] = vals["ca"] or pick(d["tx"], 0x03, 16)
        vals["cb"] = vals["cb"] or pick(d["rx"], 0x03, 16)

    missing = [k for k, v in vals.items() if v is None]
    print("have:", ", ".join(k for k, v in vals.items() if v) or "nothing")
    if missing:
        print("missing:", ", ".join(missing))

    ok = False
    ok |= report("Ca vs OUR key/Na", vals["ca"], combos(vals["our_pub"], vals["na"]))
    ok |= report("Cb vs PEER key/Nb", vals["cb"], combos(vals["peer_pub"], vals["nb"]))
    ok |= report("Cb vs xcross(peer,our)/Nb", vals["cb"], xcross(vals["peer_pub"], vals["our_pub"], vals["nb"]))
    ok |= report("Ca vs xcross(our,peer)/Na", vals["ca"], xcross(vals["our_pub"], vals["peer_pub"], vals["na"]))
    # role mix-ups seen in the wild
    ok |= report("Cb vs OUR key/Nb", vals["cb"], combos(vals["our_pub"], vals["nb"]))
    ok |= report("Ca vs PEER key/Na", vals["ca"], combos(vals["peer_pub"], vals["na"]))

    print("\nverdict:", "a combination matched" if ok else "no known combination matched")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
