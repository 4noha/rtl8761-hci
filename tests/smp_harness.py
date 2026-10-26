"""Shared harness: host stack (Hci+L2cap+Smp) <-> FakeController <-> FakeSmpPeer."""
from __future__ import annotations

import random

from rtlhci.acl import L2cap
from rtlhci.fake import FakeController, FakeSmpPeer, FakeTransport
from rtlhci.hci import Hci
from rtlhci.smp import PairingDelegate, Smp, SmpConfig

HANDLE = 0x0040


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Delegate(PairingDelegate):
    """Plays the user: shares a passkey with the peer through `box`."""

    def __init__(self, box: dict, nc_accept: bool = True, passkey_override=None):
        self.box, self.nc_accept, self.override = box, nc_accept, passkey_override
        self.shown, self.asked, self.nc, self.keypresses = [], 0, [], []

    def display_passkey(self, handle, pk):
        self.shown.append(pk)
        self.box["pk"] = pk

    def request_passkey(self, handle):
        self.asked += 1
        if self.override is not None:
            return self.override
        peer = self.box["peer"]
        if peer.displayed_passkey is not None:
            return peer.displayed_passkey
        return self.box.setdefault("pk", 314159)

    def confirm_numeric(self, handle, value):
        self.nc.append(value)
        return self.nc_accept

    def keypress(self, handle, kind):
        self.keypresses.append(kind)


def seeded(seed: int):
    r = random.Random(seed)
    return lambda n: bytes(r.getrandbits(8) for _ in range(n))


def make(host_central: bool = True, cfg: SmpConfig | None = None, *, peer_kw: dict | None = None,
         nc_accept: bool = True, passkey_override=None, snoop=None, seed: int | None = None,
         peer_addr: str = "C0:FF:EE:00:00:01", peer_addr_type: int = 1):
    ctl = FakeController()
    h = Hci(FakeTransport(ctl, snoop=snoop), cmd_timeout_s=0.3)
    h.init_standard()
    ctl.connect_le(HANDLE, peer=peer_addr, role=0 if host_central else 1, peer_addr_type=peer_addr_type)
    h.pump(1)
    l2 = L2cap(h)
    box: dict = {}
    d = Delegate(box, nc_accept, passkey_override)
    clock = Clock()
    rng = seeded(seed) if seed is not None else None
    smp = Smp(h, l2, cfg or SmpConfig(), d, clock=clock, **({"rng": rng} if rng else {}))
    kw = dict(addr=peer_addr, addr_type=peer_addr_type,
              passkey=lambda: box["pk"] if "pk" in box else box.setdefault("pk", 314159))
    if seed is not None:
        kw["rng"] = seeded(seed + 1)
    kw.update(peer_kw or {})
    peer = FakeSmpPeer(ctl, HANDLE, initiator=not host_central, **kw)
    box["peer"] = peer
    return ctl, h, smp, peer, d, clock


def run(h, smp, until=None, n: int = 200) -> None:
    for _ in range(n):
        h.pump(1)
        if until is not None and until():
            return
        if until is None and HANDLE in smp.results:
            return


def start(host_central, h, smp, peer) -> None:
    if host_central:
        smp.pair(HANDLE)
    else:
        peer.start()
