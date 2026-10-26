"""Transport interface shared by the real USB transport and test fakes."""
from __future__ import annotations

from typing import Optional


class TransportError(Exception):
    """Raised for transport-level failures (USB errors, device gone, ...)."""


class Transport:
    """H:4-less HCI transport (USB carries packet type implicitly by endpoint).

    `snoop` (optional rtlhci.btsnoop.BtSnoopWriter) is the single capture point of the stack:
    concrete transports call `_snoop()` for every complete HCI packet they send (after a
    successful write) or deliver (after USB reassembly). Nothing above this layer records.
    """

    snoop = None

    def _snoop(self, ptype: int, pkt: bytes, received: bool) -> None:
        if self.snoop is not None:
            self.snoop.record(ptype, pkt, received)

    def send_command(self, pkt: bytes) -> None:  # opcode(2) plen(1) params
        raise NotImplementedError

    def read_event(self, timeout_ms: int) -> Optional[bytes]:  # code(1) plen(1) params
        raise NotImplementedError

    def send_acl(self, pkt: bytes) -> None:  # handle/flags(2) len(2) data
        raise NotImplementedError

    def read_acl(self, timeout_ms: int) -> Optional[bytes]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class StreamReassembler:
    """Reassemble HCI packets that USB may split across several transfers.

    hdr_len / len_off / len_size describe where the payload length sits.
    Event: hdr 2, len at 1 (1 byte). ACL: hdr 4, len at 2 (2 bytes LE).
    """

    def __init__(self, hdr_len: int, len_off: int, len_size: int):
        self.hdr_len, self.len_off, self.len_size = hdr_len, len_off, len_size
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self.buf += data
        out = []
        while len(self.buf) >= self.hdr_len:
            plen = int.from_bytes(self.buf[self.len_off:self.len_off + self.len_size], "little")
            total = self.hdr_len + plen
            if len(self.buf) < total:
                break
            out.append(bytes(self.buf[:total]))
            del self.buf[:total]
        return out

    def reset(self) -> None:
        self.buf.clear()
