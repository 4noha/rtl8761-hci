import os
import struct

import pytest

from btsnoop_check import SnoopFormatError, l2cap_frames, parse, validate
from rtlhci.acl import CID_SIGNALING, L2cap, SIG, build_sig
from rtlhci.btsnoop import EPOCH_DELTA_US, BtSnoopWriter, H4_CMD, H4_EVT, unix_to_btsnoop_us
from rtlhci.fake import FakeController, FakeTransport, FakeUsbDevice, FakeUsbUtil
from rtlhci.hci import Hci
from rtlhci.usb_transport import UsbTransport


class Clock:
    def __init__(self, t=1_761_350_400.0):  # 2025-10-25 00:00 UTC
        self.t = t

    def __call__(self):
        self.t += 0.000250
        return self.t


def test_header_and_record_layout(tmp_path):
    p = tmp_path / "a.btsnoop"
    w = BtSnoopWriter(str(p), clock=lambda: 1.5)
    w.record(H4_CMD, bytes.fromhex("030c00"), received=False)
    w.record(H4_EVT, bytes.fromhex("0e0401030c00"), received=True)
    w.close()
    b = p.read_bytes()
    assert b[:16] == b"btsnoop\0" + struct.pack(">II", 1, 1002)
    orig, incl, flags, drops, ts = struct.unpack(">IIIIq", b[16:40])
    assert (orig, incl, flags, drops) == (4, 4, 0x02, 0)
    assert ts == 1_500_000 + 0x00DCDDB30F2F8000
    assert b[40:44] == bytes.fromhex("01030c00")
    assert struct.unpack(">I", b[52:56])[0] == 0x03  # event: received | cmd/evt
    assert EPOCH_DELTA_US == 0x00DCDDB30F2F8000
    assert unix_to_btsnoop_us(0) == EPOCH_DELTA_US


def test_usb_transport_records_every_packet_once_with_h4_type(tmp_path):
    p = tmp_path / "usb.btsnoop"
    snoop = BtSnoopWriter(str(p), clock=Clock())
    ctl = FakeController()
    t = UsbTransport(FakeUsbDevice(ctl), usb_util=FakeUsbUtil(), plat="Darwin", snoop=snoop)
    h = Hci(t, cmd_timeout_s=0.5)
    h.init_standard()
    h.read_local_name()  # 255-byte event reassembled from 16 interrupt chunks -> ONE record
    ctl.connect_bredr(0x40)
    h.pump(5)
    L2cap(h)
    ctl.send_l2cap(0x40, CID_SIGNALING, build_sig(SIG.ECHO_REQ, 1, b"x" * 200), frag=300)
    h.pump(5)
    snoop.close()
    recs = validate(p.read_bytes())
    cmds = [r for r in recs if r.data[0] == 1]
    evts = [r for r in recs if r.data[0] == 4]
    acl = [r for r in recs if r.data[0] == 2]
    assert len(cmds) == len(ctl.cmds)
    assert [r.data[1:] for r in cmds] == ctl.cmds
    assert any(len(r.data) == 1 + 2 + 252 for r in evts)  # Read Local Name complete (16 USB chunks)
    assert {r.received for r in acl} == {True, False}
    assert all(r.flags & 2 == 0 for r in acl)
    fr = l2cap_frames(recs)
    assert (True, 0x40, CID_SIGNALING) == fr[0][:3] and (False, 0x40, CID_SIGNALING) == fr[1][:3]
    # host trace and snoop agree on ACL tx
    assert [r.data[1:] for r in acl if not r.received] == [p for k, p in h.trace if k == "acl>"]


def test_rotation_keeps_n_files_and_each_is_valid(tmp_path):
    p = tmp_path / "rot.btsnoop"
    w = BtSnoopWriter(str(p), max_bytes=200, keep=2, clock=Clock())
    for i in range(40):
        w.record(H4_CMD, struct.pack("<HB", 0x0C03, 4) + bytes([i] * 4), received=False)
    w.close()
    assert w.rotations > 2 and w.total_records == 40 and w.drops == 0
    files = sorted(os.listdir(tmp_path))
    assert files == ["rot.btsnoop", "rot.btsnoop.1", "rot.btsnoop.2"]
    for f in files:
        b = (tmp_path / f).read_bytes()
        assert len(b) <= 200
        assert validate(b)


def test_drops_counter_and_never_raises(tmp_path):
    p = tmp_path / "d.btsnoop"
    w = BtSnoopWriter(str(p), clock=Clock())
    w.record(H4_CMD, bytes.fromhex("030c00"), False)

    class Broken:
        def write(self, b):
            raise OSError(28, "No space left on device")

        def flush(self):
            pass
    real, w._f = w._f, Broken()
    assert w.record(H4_CMD, bytes.fromhex("030c00"), False) is False
    assert w.record(H4_CMD, bytes.fromhex("030c00"), False) is False
    w._f = real
    w.record(H4_EVT, bytes.fromhex("0e0401030c00"), True)
    w.close()
    assert w.record(H4_CMD, bytes.fromhex("030c00"), False) is False  # after close: dropped
    recs = validate(p.read_bytes())
    assert [r.drops for r in recs] == [0, 2] and w.drops == 3


def test_flush_safe_partial_file_is_valid(tmp_path):
    p = tmp_path / "f.btsnoop"
    w = BtSnoopWriter(str(p), clock=Clock())
    w.record(H4_CMD, bytes.fromhex("030c00"), False)
    # without close(): what is on disk must already be a valid capture
    assert len(validate(p.read_bytes())) == 1
    w.close()


def test_snaplen_truncates(tmp_path):
    p = tmp_path / "s.btsnoop"
    w = BtSnoopWriter(str(p), snaplen=8, clock=Clock())
    w.record(0x02, struct.pack("<HH", 0x40, 20) + bytes(20), True)
    w.close()
    r = validate(p.read_bytes())[0]
    assert (r.orig, r.incl) == (25, 8)


def test_validator_rejects_garbage():
    with pytest.raises(SnoopFormatError):
        validate(b"notsnoop" + bytes(8))
    good = b"btsnoop\0" + struct.pack(">II", 1, 1002)
    with pytest.raises(SnoopFormatError):
        validate(good + struct.pack(">IIIIq", 4, 4, 2, 0, 0x00E03AB44A676001) + b"\x01\x03\x0c\x05")
    with pytest.raises(SnoopFormatError):
        parse(good + bytes(10))


def test_fake_transport_snoop_matches_trace(tmp_path):
    p = tmp_path / "fake.btsnoop"
    with BtSnoopWriter(str(p), clock=Clock()) as w:
        h = Hci(FakeTransport(FakeController(), snoop=w), cmd_timeout_s=0.3)
        h.init_standard()
    recs = validate(p.read_bytes())
    want = [(1 if k == "cmd" else 4, v) for k, v in h.trace]
    assert [(r.data[0], r.data[1:]) for r in recs] == want


# ------------------------------------------------------------------ pairing capture example
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "example.btsnoop")


def test_example_capture_is_valid_and_contains_full_sc_pairing():
    recs = validate(open(DATA, "rb").read())
    smp = [(rx, p[0]) for rx, h, cid, p in l2cap_frames(recs) if cid == 0x0006]
    assert smp == [
        (False, 0x01), (True, 0x02),             # Pairing Request / Response
        (False, 0x0C), (True, 0x0C),             # Public Keys (65 B, ACL-fragmented by the peer)
        (False, 0x03), (True, 0x03),             # Ca, Cb
        (False, 0x04), (True, 0x04),             # Na, Nb
        (False, 0x0D), (True, 0x0D),             # DHKey checks Ea, Eb
        (True, 0x08), (True, 0x09), (True, 0x0A),   # responder keys: IRK, identity addr, CSRK
        (False, 0x08), (False, 0x09), (False, 0x0A),
    ]
    cmds = [struct.unpack_from("<H", r.data, 1)[0] for r in recs if r.data[0] == 1]
    assert 0x2019 in cmds                                  # LE_Start_Encryption
    assert any(r.data[:2] == b"\x04\x08" for r in recs)    # Encryption Change
    assert recs[-1].drops == 0


def test_example_capture_is_reproducible(tmp_path):
    from make_example_btsnoop import generate
    out = tmp_path / "x.btsnoop"
    r, _ = generate(str(out))
    assert r.success
    assert out.read_bytes() == open(DATA, "rb").read()
