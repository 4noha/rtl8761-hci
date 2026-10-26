"""Tests for the offline confirm solver (smp_solve.py).

The solver only parses captured SMP PDUs and evaluates f4 variants, so a synthetic
log is enough to lock the parsing rules used when a real capture is analysed.
"""
import smp_solve as S
from rtlhci import smp_crypto as C


LOG = """\
INFO rtlhci.smp: smp pdu tx hex=01030009100707
DEBUG rtlhci.smp: smp > 0x010 PAIRING_REQUEST 01030009100707
INFO rtlhci.smp: smp pdu hex=0203000d100707
INFO rtlhci.smp: smp pdu tx hex=0c{ourpub}
INFO rtlhci.smp: smp pdu hex=0c{peerpub}
INFO rtlhci.smp: smp pdu tx hex=03{ca}
INFO rtlhci.smp: smp pdu hex=03{cb}
INFO rtlhci.smp: smp pdu tx hex=04{na}
INFO rtlhci.smp: smp pdu hex=04{nb}
"""


def test_parse_log_separates_directions(tmp_path):
    our_pub = C.DEBUG_PUBLIC_KEY
    peer_pub = C.public_key(bytes.fromhex("bd1a3ccda6b8995899b740eb7b60ff4a503f10d2e3b3c974385fc5a3d4f6493f"))
    na, nb = bytes(range(16)), bytes(range(16, 32))
    ca = C.f4(our_pub[:32], our_pub[32:], na, 0)
    cb = C.f4(peer_pub[:32], peer_pub[32:], nb, 0)
    p = tmp_path / "log.txt"
    p.write_text(LOG.format(ourpub=our_pub.hex(), peerpub=peer_pub.hex(),
                            ca=ca.hex(), cb=cb.hex(), na=na.hex(), nb=nb.hex()))
    d = S.parse_log(str(p))
    assert S.pick(d["tx"], 0x0C, 64) == our_pub
    assert S.pick(d["rx"], 0x0C, 64) == peer_pub
    assert S.pick(d["tx"], 0x03, 16) == ca
    assert S.pick(d["rx"], 0x03, 16) == cb
    assert S.pick(d["tx"], 0x04, 16) == na
    assert S.pick(d["rx"], 0x04, 16) == nb


def test_combos_cover_order_and_z():
    pub = C.DEBUG_PUBLIC_KEY
    rnd = bytes(range(16))
    got = dict(S.combos(pub, rnd))
    assert set(got) == {"XY z=0x00", "XY z=0x80", "YX z=0x00", "YX z=0x80"}
    assert len(set(got.values())) == 4
    assert got["XY z=0x00"] == C.f4(pub[:32], pub[32:], rnd, 0)


def test_combos_need_complete_material():
    assert list(S.combos(None, bytes(16))) == []
    assert list(S.combos(C.DEBUG_PUBLIC_KEY, None)) == []
