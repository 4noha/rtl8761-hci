"""ACL data packets and L2CAP basic framing (fragmentation + reassembly).

ACL header (Core Vol 4 Part E 5.4.2):
  handle[0:12] | PB flag[12:14] | BC flag[14:16]  (LE16), data_total_len (LE16)
PB: 0b00 first non-automatically-flushable (required for LE),
    0b01 continuing fragment, 0b10 first automatically-flushable (BR/EDR default).
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger("rtlhci.acl")

PB_FIRST_NONFLUSH = 0b00
PB_CONT = 0b01
PB_FIRST_FLUSH = 0b10

CID_SIGNALING = 0x0001
CID_CONNLESS = 0x0002
CID_ATT = 0x0004
CID_LE_SIGNALING = 0x0005
CID_SMP = 0x0006
CID_BREDR_SMP = 0x0007


@dataclass
class AclPacket:
    handle: int
    pb: int
    bc: int
    data: bytes


def build_acl(handle: int, pb: int, data: bytes, bc: int = 0) -> bytes:
    hdr = (handle & 0x0FFF) | ((pb & 3) << 12) | ((bc & 3) << 14)
    return struct.pack("<HH", hdr, len(data)) + data


def parse_acl(pkt: bytes) -> AclPacket:
    if len(pkt) < 4:
        raise ValueError("ACL packet too short")
    hdr, ln = struct.unpack_from("<HH", pkt)
    if len(pkt) != 4 + ln:
        raise ValueError(f"ACL length mismatch {len(pkt) - 4} != {ln}")
    return AclPacket(hdr & 0x0FFF, (hdr >> 12) & 3, (hdr >> 14) & 3, bytes(pkt[4:]))


def build_l2cap(cid: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload), cid) + payload


def fragment_l2cap(handle: int, cid: int, payload: bytes, mtu: int, le: bool) -> list[bytes]:
    """Split an L2CAP B-frame into ACL packets of at most `mtu` data bytes."""
    if mtu <= 0:
        raise ValueError("ACL MTU unknown; call read_buffer_size() first")
    frame = build_l2cap(cid, payload)
    first_pb = PB_FIRST_NONFLUSH if le else PB_FIRST_FLUSH
    out = []
    for off in range(0, len(frame), mtu):
        out.append(build_acl(handle, first_pb if off == 0 else PB_CONT, frame[off:off + mtu]))
    return out


class L2capReassembler:
    """Per-handle reassembly of ACL fragments into (handle, cid, payload)."""

    def __init__(self, on_frame: Callable[[int, int, bytes], None]):
        self.on_frame = on_frame
        self.partial: dict[int, bytearray] = {}
        self.errors = 0

    def feed(self, pkt: bytes) -> None:
        a = parse_acl(pkt)
        if a.pb in (PB_FIRST_NONFLUSH, PB_FIRST_FLUSH):
            if a.handle in self.partial:
                log.warning("handle 0x%03x: new start while %d bytes pending; dropping",
                            a.handle, len(self.partial[a.handle]))
                self.errors += 1
            self.partial[a.handle] = bytearray(a.data)
        elif a.pb == PB_CONT:
            if a.handle not in self.partial:
                log.warning("handle 0x%03x: continuation without start; dropping", a.handle)
                self.errors += 1
                return
            self.partial[a.handle] += a.data
        else:
            self.errors += 1
            return
        buf = self.partial[a.handle]
        if len(buf) < 4:
            return
        ln, cid = struct.unpack_from("<HH", buf)
        if len(buf) < 4 + ln:
            return
        if len(buf) > 4 + ln:
            log.warning("handle 0x%03x: %d extra bytes after L2CAP frame", a.handle, len(buf) - 4 - ln)
            self.errors += 1
        del self.partial[a.handle]
        self.on_frame(a.handle, cid, bytes(buf[4:4 + ln]))


# ----------------------------------------------------------- L2CAP signaling
class SIG:
    COMMAND_REJECT = 0x01
    CONNECTION_REQ = 0x02
    CONNECTION_RSP = 0x03
    CONFIGURE_REQ = 0x04
    CONFIGURE_RSP = 0x05
    DISCONNECTION_REQ = 0x06
    DISCONNECTION_RSP = 0x07
    ECHO_REQ = 0x08
    ECHO_RSP = 0x09
    INFORMATION_REQ = 0x0A
    INFORMATION_RSP = 0x0B
    CONN_PARAM_UPDATE_REQ = 0x12
    CONN_PARAM_UPDATE_RSP = 0x13
    LE_CREDIT_CONN_REQ = 0x14
    LE_CREDIT_CONN_RSP = 0x15
    FLOW_CONTROL_CREDIT = 0x16


def build_sig(code: int, ident: int, data: bytes) -> bytes:
    return struct.pack("<BBH", code, ident, len(data)) + data


def parse_sig(payload: bytes) -> list[tuple[int, int, bytes]]:
    """A BR/EDR signaling frame may carry several commands; LE carries one."""
    out, i = [], 0
    while i + 4 <= len(payload):
        code, ident, ln = struct.unpack_from("<BBH", payload, i)
        out.append((code, ident, bytes(payload[i + 4:i + 4 + ln])))
        i += 4 + ln
    return out


class L2cap:
    """Minimal L2CAP mux on top of Hci: routes frames per CID, answers echo/info,
    rejects unknown signaling. Enough to hang ATT/SMP/SDP/RFCOMM work on later."""

    def __init__(self, hci):
        self.hci = hci
        self.rx = L2capReassembler(self._on_frame)
        self.cid_handlers: dict[int, Callable[[int, bytes], None]] = {}
        self.ident = 0
        self.unhandled: list[tuple[int, int, bytes]] = []
        hci.acl_handlers.append(self.rx.feed)

    def next_ident(self) -> int:
        self.ident = self.ident % 255 + 1
        return self.ident

    def send(self, handle: int, cid: int, payload: bytes) -> None:
        le = handle in self.hci.le_handles
        mtu = (self.hci.le_acl_mtu if le else 0) or self.hci.acl_mtu
        for pkt in fragment_l2cap(handle, cid, payload, mtu, le):
            self.hci.send_acl_packet(pkt, handle)

    def _on_frame(self, handle: int, cid: int, payload: bytes) -> None:
        if cid in self.cid_handlers:
            self.cid_handlers[cid](handle, payload)
        elif cid in (CID_SIGNALING, CID_LE_SIGNALING):
            self._on_sig(handle, cid, payload)
        else:
            self.unhandled.append((handle, cid, payload))

    def _on_sig(self, handle: int, cid: int, payload: bytes) -> None:
        for code, ident, data in parse_sig(payload):
            if code == SIG.ECHO_REQ:
                self.send(handle, cid, build_sig(SIG.ECHO_RSP, ident, data))
            elif code == SIG.INFORMATION_REQ and cid == CID_SIGNALING:
                itype = struct.unpack_from("<H", data)[0]
                if itype == 0x0002:   # extended features: none
                    rsp = struct.pack("<HHI", itype, 0, 0)
                elif itype == 0x0003:  # fixed channels: signaling + (BR/EDR) SMP
                    rsp = struct.pack("<HHQ", itype, 0, (1 << 1) | (1 << 7))
                else:
                    rsp = struct.pack("<HH", itype, 1)  # not supported
                self.send(handle, cid, build_sig(SIG.INFORMATION_RSP, ident, rsp))
            elif code in (SIG.ECHO_RSP, SIG.INFORMATION_RSP, SIG.COMMAND_REJECT,
                          SIG.CONN_PARAM_UPDATE_RSP):
                self.unhandled.append((handle, cid, build_sig(code, ident, data)))
            elif code == SIG.CONN_PARAM_UPDATE_REQ and cid == CID_LE_SIGNALING:
                # accept=0x0000; actual LE Connection Update is left to the caller
                self.unhandled.append((handle, cid, build_sig(code, ident, data)))
                self.send(handle, cid, build_sig(SIG.CONN_PARAM_UPDATE_RSP, ident, b"\x00\x00"))
            elif code == SIG.CONNECTION_REQ and cid == CID_SIGNALING:
                psm, scid = struct.unpack_from("<HH", data)
                # refuse: PSM not supported (dcid 0, result 0x0002, status 0)
                self.unhandled.append((handle, cid, build_sig(code, ident, data)))
                self.send(handle, cid, build_sig(SIG.CONNECTION_RSP, ident,
                                                 struct.pack("<HHHH", 0, scid, 0x0002, 0)))
            else:
                # Command Not Understood
                self.send(handle, cid, build_sig(SIG.COMMAND_REJECT, ident, b"\x00\x00"))
