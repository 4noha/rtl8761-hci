import struct
from rtlhci.att import (parse_read_by_group, parse_read_by_type, parse_find_info,
                        uuid_repr, AttClient, AttError)


def test_uuid_repr():
    assert uuid_repr(struct.pack("<H", 0x180F)) == "0x180f"
    assert uuid_repr(bytes(range(16))) == "0f0e0d0c-0b0a-0908-0706-050403020100"


def test_parse_read_by_group():
    pdu = bytes([0x11, 6]) + struct.pack("<HH", 1, 5) + struct.pack("<H", 0x1800) \
        + struct.pack("<HH", 6, 9) + struct.pack("<H", 0x1801)
    rows = parse_read_by_group(pdu)
    assert rows == [(1, 5, "0x1800"), (6, 9, "0x1801")]


def test_parse_read_by_type():
    pdu = bytes([0x09, 7]) + struct.pack("<HBH", 3, 0x02, 4) + struct.pack("<H", 0x2A00)
    rows = parse_read_by_type(pdu)
    assert rows == [(3, 0x02, 4, "0x2a00")]


def test_parse_find_info():
    pdu = bytes([0x05, 0x01]) + struct.pack("<HH", 2, 0x2800)
    assert parse_find_info(pdu) == [(2, "0x2800")]


def test_client_write_is_limited_to_cccd_subscription():
    """Only a single Write Request exists (for the CCCD); no write-without-response."""
    assert hasattr(AttClient, "write") and hasattr(AttClient, "subscribe")
    assert not hasattr(AttClient, "write_command")
    assert not hasattr(AttClient, "write_bulk")


def test_subscribe_encodes_cccd_value(monkeypatch):
    seen = {}
    monkeypatch.setattr(AttClient, "write", lambda self, h, v: seen.update(h=h, v=bytes(v)))
    client = object.__new__(AttClient)
    client.subscribe(0xFFEE)
    assert seen == {"h": 0xFFEE, "v": b"\x01\x00"}
    client.subscribe(0xFFEE, on=False)
    assert seen["v"] == b"\x00\x00"


class _FakeL2:
    def __init__(self):
        self.sent = []

    def send(self, handle, cid, payload):
        self.sent.append(bytes(payload))


def _client(seq, timeout=0.5):
    import time as _t
    c = object.__new__(AttClient)
    c.handle, c.rx, c.mtu = 1, [], 23
    c.timeout, c.gap = timeout, 0.0
    c.l2 = _FakeL2()
    pending = list(seq)

    def pump(_s):
        if pending:
            c.rx.append(pending.pop(0))
        else:
            _t.sleep(0.01)
    c._pump = pump
    return c


def test_request_tolerates_error_then_response():
    """Some peers send an application error (0x81) and the real response right after."""
    c = _client([bytes([0x01, 0x0A, 0xED, 0xFF, 0x81]),
                 bytes([0x0B, 0xDE, 0xAD])], timeout=2.0)
    assert c.request(0x0A) == bytes([0x0B, 0xDE, 0xAD])
    assert c.l2.sent[0] == bytes([0x0A])


def test_request_raises_when_only_error_arrives():
    c = _client([bytes([0x01, 0x0A, 0xED, 0xFF, 0x81])], timeout=2.0)
    try:
        c.request(0x0A)
    except AttError as exc:
        assert exc.code == 0x81
    else:
        raise AssertionError("AttError not raised")
