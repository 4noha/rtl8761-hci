import struct
import pytest
from rtlhci.acl import (build_acl, parse_acl, fragment_l2cap, L2capReassembler, L2cap, build_sig,
                        parse_sig, SIG, CID_SIGNALING, CID_LE_SIGNALING, CID_ATT, PB_CONT, PB_FIRST_FLUSH,
                        PB_FIRST_NONFLUSH)
from rtlhci.fake import FakeController, FakeTransport
from rtlhci.hci import Hci, HciTimeout


def test_acl_header_roundtrip():
    p = build_acl(0x0ABC, PB_CONT, b"xyz", bc=0)
    assert p[:4] == struct.pack("<HH", 0x1ABC, 3)
    a = parse_acl(p)
    assert (a.handle, a.pb, a.data) == (0xABC, PB_CONT, b"xyz")
    with pytest.raises(ValueError):
        parse_acl(p[:-1])


def test_fragment_and_reassemble():
    payload = bytes(range(256)) * 3
    frags = fragment_l2cap(0x40, CID_ATT, payload, mtu=27, le=True)
    assert parse_acl(frags[0]).pb == PB_FIRST_NONFLUSH
    assert all(parse_acl(f).pb == PB_CONT for f in frags[1:])
    assert all(len(parse_acl(f).data) <= 27 for f in frags)
    got = []
    r = L2capReassembler(lambda h, c, p: got.append((h, c, p)))
    for f in frags:
        r.feed(f)
    assert got == [(0x40, CID_ATT, payload)]
    assert parse_acl(fragment_l2cap(1, 1, b"a", 10, le=False)[0]).pb == PB_FIRST_FLUSH


def test_reassembler_errors():
    got = []
    r = L2capReassembler(lambda *a: got.append(a))
    r.feed(build_acl(1, PB_CONT, b"zz"))
    assert r.errors == 1 and not got
    r.feed(build_acl(1, PB_FIRST_FLUSH, struct.pack("<HH", 10, 4) + b"ab"))
    r.feed(build_acl(1, PB_FIRST_FLUSH, struct.pack("<HH", 1, 4) + b"c"))
    assert r.errors == 2 and got == [(1, 4, b"c")]


def test_multi_sig_parse():
    s = build_sig(SIG.ECHO_REQ, 1, b"hi") + build_sig(SIG.INFORMATION_REQ, 2, b"\x02\x00")
    assert parse_sig(s) == [(SIG.ECHO_REQ, 1, b"hi"), (SIG.INFORMATION_REQ, 2, b"\x02\x00")]


def setup_link(le=False, **kw):
    ctl = FakeController(**kw)
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.3)
    h.init_standard()
    (ctl.connect_le if le else ctl.connect_bredr)(0x0040)
    h.pump(1)
    return ctl, h, L2cap(h)


def test_l2cap_echo_and_info_and_reject_over_acl():
    ctl, h, l2 = setup_link()
    ctl.send_l2cap(0x40, CID_SIGNALING, build_sig(SIG.ECHO_REQ, 7, b"ping" * 20))
    ctl.send_l2cap(0x40, CID_SIGNALING, build_sig(SIG.INFORMATION_REQ, 8, b"\x03\x00"))
    ctl.send_l2cap(0x40, CID_SIGNALING, build_sig(SIG.CONNECTION_REQ, 9, struct.pack("<HH", 0x0001, 0x0040)))
    ctl.send_l2cap(0x40, CID_SIGNALING, build_sig(0x55, 10, b""))
    h.pump(1)
    out = []
    r = L2capReassembler(lambda hh, c, p: out.append(parse_sig(p)[0]))
    for p in ctl.acl_in:
        r.feed(p)
    codes = [(c, i) for c, i, _ in out]
    assert codes == [(SIG.ECHO_RSP, 7), (SIG.INFORMATION_RSP, 8), (SIG.CONNECTION_RSP, 9),
                     (SIG.COMMAND_REJECT, 10)]
    assert out[0][2] == b"ping" * 20
    assert struct.unpack("<HHHH", out[2][2])[2] == 0x0002  # PSM not supported
    h.pump(1)
    assert h.acl_credits == 6  # all credits returned via Number Of Completed Packets


def test_le_link_uses_le_buffers_and_cid_handler():
    ctl, h, l2 = setup_link(le=True)
    assert 0x40 in h.le_handles
    got = []
    l2.cid_handlers[CID_ATT] = lambda hh, p: got.append(p)
    ctl.send_l2cap(0x40, CID_ATT, b"\x02\x17\x00", pb_first=PB_FIRST_NONFLUSH)
    h.pump(1)
    assert got == [b"\x02\x17\x00"]
    l2.send(0x40, CID_ATT, bytes(600))
    assert len(ctl.acl_in) == 3  # 604 bytes / 251
    h.pump(1)
    assert h.le_acl_credits == 8 and h.acl_credits == 6


def test_acl_credit_exhaustion_times_out():
    ctl, h, l2 = setup_link(acl_num=1)
    ctl.on_acl = lambda pkt: ctl.acl_in.append(pkt)  # controller never completes
    h.send_acl_packet(build_acl(0x40, PB_FIRST_FLUSH, b"\x00\x00\x01\x00"), 0x40)
    with pytest.raises(HciTimeout):
        h.send_acl_packet(build_acl(0x40, PB_FIRST_FLUSH, b"\x00\x00\x01\x00"), 0x40)
