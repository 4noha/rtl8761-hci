#!/usr/bin/env python3
"""Regenerate tests/data/example.btsnoop: one complete LE Secure Connections Numeric Comparison
pairing (host = central) over the fake controller, deterministic (seeded RNG, fixed clock).

Contents: HCI bring-up, LE connection, Pairing Request/Response, Public Key x2, Confirm,
Random x2, DHKey Check x2, LE_Start_Encryption, Encryption Change, key distribution
(IRK, identity address, CSRK each way). SIMULATED -- not captured from hardware.

  python tests/make_example_btsnoop.py [out.btsnoop]
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

from rtlhci.btsnoop import BtSnoopWriter  # noqa: E402
from rtlhci.smp import AUTH_BONDING, AUTH_MITM, AUTH_SC, IO, SmpConfig  # noqa: E402
from smp_harness import HANDLE, make, run  # noqa: E402

DEFAULT = os.path.join(HERE, "data", "example.btsnoop")


class StepClock:
    def __init__(self, t: float = 1_761_350_400.0):  # 2025-10-25 00:00:00 UTC, 1 ms per packet
        self.t = t

    def __call__(self) -> float:
        self.t += 0.001
        return self.t


def generate(path: str = DEFAULT):
    w = BtSnoopWriter(path, clock=StepClock())
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(io_cap=IO.DISPLAY_YES_NO, mitm=True), snoop=w, seed=7,
                                   peer_kw=dict(io=IO.DISPLAY_YES_NO, auth=AUTH_BONDING | AUTH_MITM | AUTH_SC))
    smp.pair(HANDLE)
    run(h, smp)
    w.close()
    return smp.results[HANDLE], peer


if __name__ == "__main__":
    r, _ = generate(sys.argv[1] if len(sys.argv) > 1 else DEFAULT)
    print(r)
