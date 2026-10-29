"""RFCOMM (TS 07.10) の最小実装。

できること:
  - DLCI 0（マルチプレクサ）と DLCI 2（サーバチャネル 1）への SABM
  - UIH フレームの送受信（credit-based flow control 非対応・FCS 無し UIH）
  - 受信フレームのデコード（1/2 オクテット長、FCS 付き/無しの両対応）

NP1 の ANWStack は仕様から外れた L2CAP 挙動をする（acl.L2cap.connect_psm 参照）ため、
フレームはそのまま投げて生バイトを観測する方針。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

# TS 07.10 の FCS（多項式 x^8+x^2+x+1、初期値 0xFF、最後に 1 の補数）
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = ((_c << 1) ^ 0x07) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    _CRC_TABLE.append(_c)


def crc8(data: bytes) -> int:
    fcs = 0xFF
    for b in data:
        fcs = _CRC_TABLE[fcs ^ b]
    return 0xFF - fcs


# TS 07.10 の制御フィールド（P/F ビット 0x10 を除いた基本値）
CTRL_SABM = 0x2F
CTRL_UA = 0x63
CTRL_DM = 0x0F
CTRL_DISC = 0x43
CTRL_UIH = 0xEF
CTRL_UI = 0x03

CTRL_NAMES = {
    CTRL_SABM: "SABM", CTRL_UA: "UA", CTRL_DM: "DM", CTRL_DISC: "DISC",
    CTRL_UIH: "UIH", CTRL_UI: "UI",
}


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([(n << 1) | 0x01])
    return bytes([(n & 0x7F) << 1, (n >> 7) & 0xFF])


def decode_length(buf: bytes, i: int):
    b0 = buf[i]
    if b0 & 1:
        return (b0 >> 1), i + 1
    b1 = buf[i + 1]
    return ((b1 << 7) | (b0 >> 1)), i + 2


@dataclass
class Frame:
    address: int
    dlci: int
    cr: int
    control: int
    info: bytes
    fcs_ok: bool | None

    @property
    def kind(self) -> str:
        return CTRL_NAMES.get(self.control, f"{self.control:#04x}")

    def __repr__(self) -> str:
        return (f"Frame(dlci={self.dlci} cr={self.cr} {self.kind} "
                f"info={self.info.hex()} fcs={self.fcs_ok})")


def encode_frame(dlci: int, control: int, info: bytes = b"", *,
                 cr: int = 1, pf: bool = True, fcs: bool | None = None) -> bytes:
    address = (dlci << 2) | ((cr & 1) << 1) | 0x01
    if control == CTRL_UIH:
        # UIH は P/F ビットを使わず、FCS も既定で付けない
        pf = False
        if fcs is None:
            fcs = False
    elif fcs is None:
        fcs = True
    ctrl = control | (0x10 if pf else 0x00)
    # 非 UIH の長さフィールドは FCS オクテットを含む（TS 07.10）
    ln = len(info) + (1 if fcs else 0)
    body = bytes([address, ctrl]) + encode_length(ln)
    if fcs:
        body += bytes([crc8(body)])
    return body + info


def decode_frames(buf: bytes) -> list[Frame]:
    out, i = [], 0
    while i + 3 <= len(buf):
        address, ctrl = buf[i], buf[i + 1]
        dlci, cr = address >> 2, (address >> 1) & 1
        ln, j = decode_length(buf, i + 2)
        if j > len(buf):
            break
        base = ctrl & 0xEF
        end = j + ln
        if end > len(buf):
            break
        raw = buf[j:end]
        fcs_ok = None
        if base != CTRL_UIH and len(raw) >= 1:
            calc = crc8(buf[i:j] + raw[:-1])
            fcs_ok = (calc == raw[-1])
            info = raw[:-1]
        else:
            info = raw
        out.append(Frame(address=address, dlci=dlci, cr=cr, control=base,
                         info=bytes(info), fcs_ok=fcs_ok))
        i = end
    return out
