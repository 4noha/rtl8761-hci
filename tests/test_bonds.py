"""Bond persistence and Repeated Attempts back-off (rtlhci.smp)."""
import json
import os

import pytest

from rtlhci.smp import Bond, KeySet, SmpConfig
from smp_harness import HANDLE, make


def _bond() -> Bond:
    return Bond(
        peer=("C0:FF:EE:00:00:01", 1),
        sc=True,
        authenticated=False,
        key_size=16,
        ltk=bytes(range(16)),
        local=KeySet(ltk=bytes(range(16)), ediv=0, rand=bytes(8),
                     irk=bytes([0xAA]) * 16, identity_addr=bytes([1, 2, 3, 4, 5, 6]),
                     identity_addr_type=0, csrk=bytes([0xBB]) * 16),
        remote=KeySet(ltk=bytes([0xCC]) * 16, ediv=0x1234, rand=bytes([0xDD]) * 8,
                      irk=bytes([0xEE]) * 16, identity_addr=bytes([9, 8, 7, 6, 5, 4]),
                      identity_addr_type=1, csrk=bytes([0x11]) * 16),
    )


def test_bond_roundtrip_dict():
    b = _bond()
    d = b.to_dict()
    assert d["peer"] == ["C0:FF:EE:00:00:01", 1]
    assert json.loads(json.dumps(d)) == d          # JSON-safe
    b2 = Bond.from_dict(d)
    assert b2.peer == b.peer and b2.ltk == b.ltk
    assert b2.local.irk == b.local.irk and b2.remote.ediv == b.remote.ediv
    assert b2.remote.identity_addr == b.remote.identity_addr


def test_save_and_load_bonds(tmp_path):
    _ctl, _h, smp, _peer, _d, _clock = make()
    smp.bonds[("C0:FF:EE:00:00:01", 1)] = _bond()
    path = tmp_path / "bonds.json"
    assert smp.save_bonds(str(path)) == 1
    assert (os.stat(path).st_mode & 0o777) == 0o600

    _ctl2, _h2, smp2, _p2, _d2, _c2 = make()
    assert smp2.load_bonds(str(path)) == 1
    got = smp2.bonds[("C0:FF:EE:00:00:01", 1)]
    assert got.ltk == bytes(range(16))
    assert smp2.encrypt  # callable, bond present


def test_repeated_attempts_backoff():
    cfg = SmpConfig(repeated_attempts_limit=2, repeated_attempts_backoff_s=10.0)
    _ctl, _h, smp, _peer, _d, clock = make(cfg=cfg)
    peer = ("C0:FF:EE:00:00:01", 1)

    smp.note_pairing_failure(peer)
    assert smp.pairing_blocked_for(peer) == 0.0    # below the limit
    smp.note_pairing_failure(peer)
    assert smp.pairing_blocked_for(peer) == pytest.approx(10.0)

    clock.t += 4.0
    assert smp.pairing_blocked_for(peer) == pytest.approx(6.0)
    clock.t += 7.0
    assert smp.pairing_blocked_for(peer) == 0.0

    smp.note_pairing_success(peer)
    assert smp.pairing_blocked_for(peer) == 0.0


def test_pair_refused_while_blocked():
    cfg = SmpConfig(repeated_attempts_limit=1, repeated_attempts_backoff_s=30.0)
    _ctl, _h, smp, _peer, _d, clock = make(cfg=cfg)
    smp.note_pairing_failure(("C0:FF:EE:00:00:01", 1))
    assert smp.pair(HANDLE) is False
    clock.t += 31.0
    assert smp.pair(HANDLE) is not False           # proceeds (returns None)
