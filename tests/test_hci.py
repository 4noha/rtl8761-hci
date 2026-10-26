import struct
import pytest
from rtlhci.fake import FakeController, FakeTransport, evt, cc
from rtlhci.hci import Hci, HciError, HciTimeout, OP, EVT, parse_event, parse_ad, build_command, bdaddr_bytes
from rtlhci.transport import StreamReassembler


def mk(**kw):
    ctl = FakeController(**kw)
    return ctl, Hci(FakeTransport(ctl), cmd_timeout_s=0.3)


def test_build_command():
    assert build_command(OP.RESET) == b"\x03\x0c\x00"
    assert build_command(OP.LE_SET_SCAN_ENABLE, b"\x01\x01") == b"\x0c\x20\x02\x01\x01"


def test_reset_version_addr_buffers():
    ctl, h = mk()
    info = h.init_standard()
    assert info["version"].lmp_subver == 0x8761 and info["version"].manufacturer == 93
    assert info["bd_addr"] == "E8:48:B8:C8:20:00"
    assert info["buffer"].acl_len == 1021 and h.acl_credits == 6
    assert h.le_acl_mtu == 251 and h.le_acl_credits == 8
    assert ctl.cmds[0] == b"\x03\x0c\x00"


def test_command_error_status():
    ctl, h = mk(fail_ops={OP.READ_BD_ADDR: 0x0C})
    with pytest.raises(HciError) as e:
        h.read_bd_addr()
    assert e.value.status == 0x0C


def test_unknown_command_and_timeout():
    ctl, h = mk()
    with pytest.raises(HciError):
        h.command(0x0C7F)
    ctl.on_command = lambda pkt: None  # controller goes silent
    with pytest.raises(HciTimeout):
        h.command(OP.RESET, timeout_s=0.1)


def test_unrelated_events_are_queued_during_command():
    ctl, h = mk()
    ctl.events.append(evt(EVT.HARDWARE_ERROR, b"\x05"))
    h.read_bd_addr()
    assert [e.code for e in h.pending_events] == [EVT.HARDWARE_ERROR]
    assert h.pump(1)[0].fields["hw_code"] == 5


def test_command_credit_flow_control():
    ctl, h = mk()
    h.ncmd = 0
    ctl.events.append(cc(0x0000, b"", ncmd=1))  # NOP credit
    h.read_bd_addr()
    assert h.ncmd == 1


def adv_report(addr, data, rssi=-60, etype=0, atype=0):
    return bytes([etype, atype]) + bdaddr_bytes(addr) + bytes([len(data)]) + data + struct.pack("b", rssi)


def test_le_scan_reports():
    ctl, h = mk()
    ad = b"\x02\x01\x06" + b"\x05\x09NP-1" + b"\x03\x03\x0f\x18" + b"\x05\xff\x5d\x00\xaa\xbb"
    two = adv_report("C0:FF:EE:00:00:01", ad, -42) + adv_report("C0:FF:EE:00:00:02", b"", -80, etype=4, atype=1)
    ctl.adv_reports = [b"\x02" + two]
    seen = h.le_scan(0.05)
    r = seen["C0:FF:EE:00:00:01"]
    assert r["name"] == "NP-1" and r["rssi"] == -42 and r["flags"] == 6
    assert r["uuid16"] == ["180f"] and r["mfg"] == [(0x005D, "aabb")]
    assert seen["C0:FF:EE:00:00:02"]["addr_type"] == 1
    assert ctl.cmds[-1] == b"\x0c\x20\x02\x00\x01"  # scan disabled at end


def test_truncated_adv_report_raises():
    with pytest.raises(ValueError):
        parse_event(evt(EVT.LE_META, b"\x02\x01\x00\x00" + b"\x00" * 6 + b"\x05ab"))


def test_inquiry_results_all_formats():
    ctl, h = mk()
    a = bdaddr_bytes("00:11:22:33:44:55")
    std = evt(EVT.INQUIRY_RESULT, b"\x01" + a + b"\x01\x00\x00" + b"\x0c\x02\x5a" + b"\x34\x12")
    rssi = evt(EVT.INQUIRY_RESULT_RSSI, b"\x01" + bdaddr_bytes("00:11:22:33:44:66") + b"\x01\x00"
               + b"\x04\x04\x24" + b"\x00\x00" + struct.pack("b", -55))
    eir = b"\x0e\x09ExampleDevice"
    ext = evt(EVT.EXTENDED_INQUIRY_RESULT, b"\x01" + bdaddr_bytes("00:11:22:33:44:77") + b"\x01\x00"
              + b"\x14\x04\x24" + b"\x00\x00" + struct.pack("b", -50) + eir.ljust(240, b"\0"))
    ctl.inquiry_results = [std, rssi, ext]
    found = h.inquiry(1.28)
    assert found["00:11:22:33:44:55"]["cod"] == 0x5A020C
    assert found["00:11:22:33:44:55"]["clock_offset"] == 0x1234
    assert found["00:11:22:33:44:66"]["rssi"] == -55
    assert found["00:11:22:33:44:77"]["name"] == "ExampleDevice"
    assert ctl.cmds[-1][:3] == b"\x01\x04\x05"  # inquiry, plen 5


def test_parse_command_status_and_disconnect():
    ctl, h = mk()
    h.disconnect(0x0042)
    ev = h.wait_for(lambda e: e.code == EVT.DISCONNECTION_COMPLETE, 0.2)
    assert ev.fields["handle"] == 0x42 and ev.fields["reason"] == 0x16


def test_parse_ad_stops_on_garbage():
    assert parse_ad(b"\x02\x01\x06\x00\xff\xff") == [(1, b"\x06")]
    assert parse_ad(b"\x09\x09abc") == []


def test_stream_reassembler_split_events():
    r = StreamReassembler(2, 1, 1)
    pkt = evt(EVT.COMMAND_COMPLETE, bytes(30))
    assert r.feed(pkt[:16]) == []
    assert r.feed(pkt[16:] + pkt[:3]) == [pkt]
    assert r.feed(pkt[3:]) == [pkt]
