import os
import struct
import pytest
from conftest import FW_DIR
from rtlhci.fake import FakeController, FakeTransport
from rtlhci.hci import Hci, OP
from rtlhci import rtl
from rtlhci.rtl import (parse_epatch, fragments, FirmwareError, RtlSetup, match_ic, EXTENSION_SIG,
                        RTL_FRAG_LEN)

REAL_FW = os.path.join(FW_DIR, "rtl8761bu_fw.bin")
REAL_CFG = os.path.join(FW_DIR, "rtl8761bu_config.bin")
have_fw = pytest.mark.skipif(not os.path.exists(REAL_FW), reason="linux-firmware blob not present")


def synth_v1(project_id=14, patches=((1, b"A" * 100), (2, b"B" * 300)), fw_version=0x11223344):
    n = len(patches)
    hdr = b"Realtech" + struct.pack("<IH", fw_version, n)
    table_len = 8 * n
    off = len(hdr) + table_len
    chips, lens, offs, body = b"", b"", b"", b""
    for chip, data in patches:
        chips += struct.pack("<H", chip)
        lens += struct.pack("<H", len(data))
        offs += struct.pack("<I", off + len(body))
        body += data
    # extension is read backwards from SIG as (opcode, length, data) triples:
    # stored order is [data, length, opcode]; here: EOF marker, then project id (opcode 0, len 1)
    ext = bytes([0x00, 0x00, 0xFF]) + bytes([project_id, 0x01, 0x00])
    return hdr + chips + lens + offs + body + ext + EXTENSION_SIG


def test_synthetic_v1_selects_patch_and_writes_version():
    fw = synth_v1()
    p = parse_epatch(fw, rom_version=1)
    assert p.format == "v1" and p.project_id == 14
    assert p.payload == b"B" * 296 + struct.pack("<I", 0x11223344)
    p0 = parse_epatch(fw, rom_version=0)
    assert p0.payload[:96] == b"A" * 96


def test_v1_errors():
    with pytest.raises(FirmwareError, match="signature"):
        parse_epatch(b"NotRealtekFW" + b"\0" * 20, 0)
    with pytest.raises(FirmwareError, match="extension"):
        parse_epatch(synth_v1()[:-1] + b"\0", 0)
    with pytest.raises(FirmwareError, match="didn't find patch"):
        parse_epatch(synth_v1(), rom_version=5)
    with pytest.raises(FirmwareError, match="firmware is for"):
        parse_epatch(synth_v1(project_id=8), 1)  # 8822B blob on a 8761
    with pytest.raises(FirmwareError, match="unknown project"):
        parse_epatch(synth_v1(project_id=99), 1)


def synth_v2(rom_version=1, key_id=0):
    def subsec(eco, prio, data, kid=0):
        return struct.pack("<BBBBI", eco, prio, kid, 0, len(data)) + data
    snip = struct.pack("<HH", 3, 0) + subsec(rom_version + 1, 2, b"S2") + subsec(9, 1, b"XX") \
        + subsec(rom_version + 1, 1, b"S1")
    sec = struct.pack("<HH", 2, 0) + subsec(rom_version + 1, 0, b"K1", kid=1) + subsec(rom_version + 1, 0, b"K2", kid=2)
    body = struct.pack("<II", 1, len(snip)) + snip + struct.pack("<II", 3, len(sec)) + sec
    hdr = b"RTBTCore" + b"\x01\x02\x03\x04\x05\x06\x07\x08" + struct.pack("<I", 2)
    return hdr + body + bytes([51, 0x01, 0x00]) + EXTENSION_SIG


def test_synthetic_v2_priority_and_key():
    fw = synth_v2()
    assert parse_epatch(fw, 1, key_id=0).payload == b"S1S2"
    assert parse_epatch(fw, 1, key_id=2).payload == b"K2S1S2"


def test_fragments_index_wrap_and_end_flag():
    data = bytes(RTL_FRAG_LEN * 130 + 10)
    fr = fragments(data)
    idx = [f[0] for f in fr]
    assert idx[:3] == [0, 1, 2] and idx[127] == 0x7F and idx[128] == 1
    assert idx[-1] & 0x80 and len(fr[-1]) == 11
    assert b"".join(f[1:] for f in fr) == data
    # Linux quirk: exact multiple -> trailing empty fragment with end flag
    fr2 = fragments(bytes(RTL_FRAG_LEN * 2))
    assert len(fr2) == 3 and fr2[-1] == bytes([0x82])


def test_ic_table():
    assert match_ic(0x8761, 0x0B, 0x0A).hw_info == "rtl8761bu"
    assert match_ic(0x8761, 0x0B, 0x0A, bus=rtl.HCI_UART).hw_info == "rtl8761btv"
    assert match_ic(0x8761, 0x0E, 0x0C).hw_info == "rtl8761cu"
    assert match_ic(0xD922, 0xDFC6, 0x0A) is None


@have_fw
def test_real_rtl8761bu_blob_parses():
    fw = open(REAL_FW, "rb").read()
    p = parse_epatch(fw, rom_version=1)
    assert p.format == "v1" and p.project_id == 14 and p.fw_version == 0xDFC6D922
    assert len(p.payload) == 0x75FC


@have_fw
def test_full_setup_against_fake_controller():
    ctl = FakeController(rom_version=1)
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.5)
    info = RtlSetup(h, FW_DIR).run()
    expected = parse_epatch(open(REAL_FW, "rb").read(), 1).payload + open(REAL_CFG, "rb").read()
    assert bytes(ctl.dl_data) == expected
    assert info.downloaded == len(fragments(expected))
    assert info.final_version == (0xDFC6, 0xD922)
    assert info.rom_version == 1 and info.key_id == 0
    assert "sha256=" in info.fw_file


def test_setup_skip_firmware_and_missing_dir():
    ctl = FakeController()
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.5)
    info = RtlSetup(h, None).run(skip_firmware=True)
    assert info.ic.hw_info == "rtl8761bu" and not ctl.dl_frags
    with pytest.raises(FirmwareError, match="no firmware directory"):
        RtlSetup(h, None).run()
    with pytest.raises(FirmwareError, match="not found"):
        RtlSetup(h, "/nonexistent").run()


def test_already_patched_triggers_drop_then_redownload():
    ctl = FakeController(patched=True)
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.5)
    info = RtlSetup(h, None).run(skip_firmware=True)
    assert ctl.drop_count == 1 and info.ic is not None


def test_sticky_patched_assumes_no_upload():
    ctl = FakeController(patched="sticky")
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.5)
    info = RtlSetup(h, FW_DIR).run()
    assert info.already_patched and not ctl.dl_frags and ctl.drop_count == 1


def test_key_id_nonzero_skips_config():
    ctl = FakeController(key_id=3)
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.5)
    s = RtlSetup(h, FW_DIR)
    info = rtl.RtlInfo()
    s.identify(info)
    info.key_id = 3
    if os.path.exists(REAL_FW):
        fw, cfg = s._load_files(info)
        assert cfg is None
