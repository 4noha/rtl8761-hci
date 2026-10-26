"""Minimal ATT client: Exchange MTU, Read By Group/Type, Find Information.

Reads are the default. Two narrow extras exist for notification work:
`write()` (used only for a CCCD subscription) and notification capture.
"""
from __future__ import annotations

import os
import struct
import time

ATT_CID = 0x0004
OP_ERROR = 0x01
OP_MTU_REQ = 0x02
OP_MTU_RSP = 0x03
OP_FIND_INFO_REQ = 0x04
OP_FIND_INFO_RSP = 0x05
OP_READ_BY_TYPE_REQ = 0x08
OP_READ_BY_TYPE_RSP = 0x09
OP_READ_BY_GROUP_REQ = 0x10
OP_READ_BY_GROUP_RSP = 0x11
OP_WRITE_REQ = 0x12
OP_WRITE_RSP = 0x13
OP_HANDLE_VALUE_NTF = 0x1B
OP_HANDLE_VALUE_IND = 0x1D
OP_HANDLE_VALUE_CFM = 0x1E
ERR_ATTR_NOT_FOUND = 0x0A


class AttError(Exception):
    def __init__(self, req: int, handle: int, code: int):
        super().__init__(f"ATT error req=0x{req:02x} handle=0x{handle:04x} code=0x{code:02x}")
        self.req, self.handle, self.code = req, handle, code


def parse_read_by_group(pdu: bytes) -> list[tuple[int, int, str]]:
    if len(pdu) < 2:
        return []
    length = pdu[1]
    out = []
    i = 2
    while i + length <= len(pdu) and length >= 4:
        start, end = struct.unpack_from("<HH", pdu, i)
        uuid = pdu[i + 4:i + length]
        out.append((start, end, uuid_repr(uuid)))
        i += length
    return out


def parse_read_by_type(pdu: bytes) -> list[tuple[int, int, int, str]]:
    if len(pdu) < 2:
        return []
    length = pdu[1]
    out = []
    i = 2
    while i + length <= len(pdu) and length >= 3:
        handle = struct.unpack_from("<H", pdu, i)[0]
        props = pdu[i + 2]
        value_handle = struct.unpack_from("<H", pdu, i + 3)[0] if length >= 5 else 0
        uuid = pdu[i + 5:i + length]
        out.append((handle, props, value_handle, uuid_repr(uuid)))
        i += length
    return out


def parse_find_info(pdu: bytes) -> list[tuple[int, str]]:
    if len(pdu) < 2:
        return []
    fmt, i, out = pdu[1], 2, []
    width = 2 if fmt == 0x01 else 16
    while i + 2 + width <= len(pdu):
        handle = struct.unpack_from("<H", pdu, i)[0]
        out.append((handle, uuid_repr(pdu[i + 2:i + 2 + width])))
        i += 2 + width
    return out


def uuid_repr(raw: bytes) -> str:
    if len(raw) == 2:
        return f"0x{struct.unpack('<H', raw)[0]:04x}"
    if len(raw) == 4:
        return f"0x{struct.unpack('<I', raw)[0]:08x}"
    if len(raw) == 16:
        b = bytes(reversed(raw))
        return (f"{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}-"
                f"{b[8:10].hex()}-{b[10:16].hex()}")
    return raw.hex()


class AttClient:
    def __init__(self, hci, l2cap, handle: int):
        self.hci = hci
        self.l2 = l2cap
        self.handle = handle
        self.mtu = 23
        self.timeout = float(os.environ.get("ATT_TIMEOUT_S", "3.0"))
        self.rx: list[bytes] = []
        self.notify: list[tuple[int, bytes]] = []
        l2cap.cid_handlers[ATT_CID] = self._on_frame

    def _on_frame(self, handle: int, payload: bytes) -> None:
        if handle != self.handle or not payload:
            return
        if payload[0] in (OP_HANDLE_VALUE_NTF, OP_HANDLE_VALUE_IND) and len(payload) >= 3:
            self.notify.append((struct.unpack_from("<H", payload, 1)[0], bytes(payload[3:])))
            if payload[0] == OP_HANDLE_VALUE_IND:
                self.l2.send(self.handle, ATT_CID, bytes([OP_HANDLE_VALUE_CFM]))
            return
        # Read-only responder: MTU exchange + peer's Read By Type (Device Name) only.
        if payload[0] == OP_MTU_REQ and len(payload) >= 3:
            self.l2.send(self.handle, ATT_CID, bytes([OP_MTU_RSP]) + struct.pack("<H", self.mtu))
            return
        if payload[0] == OP_READ_BY_TYPE_REQ and len(payload) >= 7:
            start, end, typ = struct.unpack_from("<HHH", payload, 1)
            if typ == 0x2A00 and start <= 0x0003 <= end:
                name = b"Host-PC"
                body = bytes([0x09, len(name) + 2]) + struct.pack("<H", 0x0003) + name
                self.l2.send(self.handle, ATT_CID, body)
            else:
                self.l2.send(self.handle, ATT_CID, bytes([OP_ERROR, payload[0]]) + struct.pack("<H", start) + bytes([ERR_ATTR_NOT_FOUND]))
            return
        self.rx.append(bytes(payload))

    def _pump(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                self.hci.pump(50)
            except Exception:
                pass

    def request(self, op: int, body: bytes = b"", timeout: float | None = None) -> bytes:
        gap = getattr(self, "gap", 0.0)
        if gap:
            time.sleep(gap)
        if timeout is None:
            timeout = getattr(self, "timeout", 3.0)
        self.rx.clear()
        self.l2.send(self.handle, ATT_CID, bytes([op]) + body)
        end = time.monotonic() + timeout
        pending_err = None
        err_deadline = 0.0
        while time.monotonic() < end:
            self._pump(0.05)
            if self.rx:
                pdu = self.rx.pop(0)
                if not pdu:
                    continue
                if pdu[0] == OP_ERROR:
                    if pdu[1] == op:
                        # Some peers send an application error first and the real
                        # response a moment later; keep listening briefly before giving up.
                        pending_err = AttError(pdu[1], struct.unpack_from("<H", pdu, 2)[0],
                                               pdu[4] if len(pdu) > 4 else 0)
                        err_deadline = time.monotonic() + 1.0
                    continue
                if pdu[0] == op + 1:
                    return pdu
            if pending_err is not None and time.monotonic() >= err_deadline:
                raise pending_err
        if pending_err is not None:
            raise pending_err
        raise TimeoutError(f"ATT timeout for opcode 0x{op:02x}")

    def exchange_mtu(self, mtu: int = 247) -> int:
        rsp = self.request(OP_MTU_REQ, struct.pack("<H", mtu))
        self.mtu = struct.unpack_from("<H", rsp, 1)[0]
        return self.mtu

    def read_by_group(self, start: int = 1, end: int = 0xFFFF,
                      group: int = 0x2800) -> list[tuple[int, int, str]]:
        out: list[tuple[int, int, str]] = []
        cursor = start
        while cursor <= end:
            try:
                rsp = self.request(OP_READ_BY_GROUP_REQ, struct.pack("<HHH", cursor, end, group))
            except AttError as exc:
                if exc.code == ERR_ATTR_NOT_FOUND:
                    break
                raise
            rows = parse_read_by_group(rsp)
            if not rows:
                break
            out.extend(rows)
            cursor = rows[-1][1] + 1
        return out

    def read_by_type(self, start: int, end: int,
                     typ: int = 0x2803) -> list[tuple[int, int, int, str]]:
        out: list[tuple[int, int, int, str]] = []
        cursor = start
        while cursor <= end:
            try:
                rsp = self.request(OP_READ_BY_TYPE_REQ, struct.pack("<HHH", cursor, end, typ))
            except AttError as exc:
                if exc.code == ERR_ATTR_NOT_FOUND:
                    break
                raise
            rows = parse_read_by_type(rsp)
            if not rows:
                break
            out.extend(rows)
            cursor = rows[-1][0] + 1
        return out

    def write(self, handle: int, value: bytes) -> None:
        """Single Write Request (used for the CCCD subscription only)."""
        self.request(OP_WRITE_REQ, struct.pack("<H", handle) + bytes(value))

    def subscribe(self, cccd_handle: int, on: bool = True) -> None:
        self.write(cccd_handle, b"\x01\x00" if on else b"\x00\x00")

    def read(self, handle: int) -> bytes:
        rsp = self.request(0x0A, struct.pack("<H", handle))
        return rsp[1:]

    def find_info(self, start: int = 1, end: int = 0xFFFF) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        cursor = start
        while cursor <= end:
            try:
                rsp = self.request(OP_FIND_INFO_REQ, struct.pack("<HH", cursor, end))
            except AttError as exc:
                if exc.code == ERR_ATTR_NOT_FOUND:
                    break
                raise
            rows = parse_find_info(rsp)
            if not rows:
                break
            out.extend(rows)
            cursor = rows[-1][0] + 1
        return out
