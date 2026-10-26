"""HCI core: packet builders, event parser, synchronous command flow."""
from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .transport import Transport, TransportError

log = logging.getLogger("rtlhci.hci")


def opcode(ogf: int, ocf: int) -> int:
    return (ogf << 10) | ocf


class OP:
    # Link control (OGF 0x01)
    INQUIRY = 0x0401
    INQUIRY_CANCEL = 0x0402
    CREATE_CONNECTION = 0x0405
    DISCONNECT = 0x0406
    ACCEPT_CONNECTION_REQUEST = 0x0409
    REMOTE_NAME_REQUEST = 0x0419
    # Controller & baseband (OGF 0x03)
    SET_EVENT_MASK = 0x0C01
    RESET = 0x0C03
    WRITE_LOCAL_NAME = 0x0C13
    READ_LOCAL_NAME = 0x0C14
    WRITE_SCAN_ENABLE = 0x0C1A
    WRITE_CLASS_OF_DEVICE = 0x0C24
    WRITE_INQUIRY_MODE = 0x0C45
    WRITE_LE_HOST_SUPPORTED = 0x0C6D
    # Informational (OGF 0x04)
    READ_LOCAL_VERSION = 0x1001
    READ_LOCAL_COMMANDS = 0x1002
    READ_LOCAL_FEATURES = 0x1003
    READ_BUFFER_SIZE = 0x1005
    READ_BD_ADDR = 0x1009
    # LE (OGF 0x08)
    LE_SET_EVENT_MASK = 0x2001
    LE_READ_BUFFER_SIZE = 0x2002
    LE_SET_SCAN_PARAMETERS = 0x200B
    LE_SET_SCAN_ENABLE = 0x200C
    LE_SET_EXT_SCAN_PARAMETERS = 0x2041
    LE_SET_EXT_SCAN_ENABLE = 0x2042
    LE_CREATE_CONNECTION = 0x200D
    LE_CREATE_CONNECTION_CANCEL = 0x200E
    LE_ENCRYPT = 0x2017
    LE_RAND = 0x2018
    LE_START_ENCRYPTION = 0x2019
    LE_LTK_REQUEST_REPLY = 0x201A
    LE_LTK_REQUEST_NEG_REPLY = 0x201B
    # Realtek vendor (OGF 0x3F)
    RTL_DOWNLOAD = 0xFC20
    RTL_READ_REG16 = 0xFC61
    RTL_DROP_FW = 0xFC66
    RTL_READ_ROM_VERSION = 0xFC6D


class EVT:
    INQUIRY_COMPLETE = 0x01
    INQUIRY_RESULT = 0x02
    CONNECTION_COMPLETE = 0x03
    CONNECTION_REQUEST = 0x04
    DISCONNECTION_COMPLETE = 0x05
    REMOTE_NAME_COMPLETE = 0x07
    ENCRYPTION_CHANGE = 0x08
    COMMAND_COMPLETE = 0x0E
    COMMAND_STATUS = 0x0F
    HARDWARE_ERROR = 0x10
    NUM_COMPLETED_PACKETS = 0x13
    INQUIRY_RESULT_RSSI = 0x22
    EXTENDED_INQUIRY_RESULT = 0x2F
    ENCRYPTION_KEY_REFRESH_COMPLETE = 0x30
    LE_META = 0x3E
    VENDOR = 0xFF


class LE_SUB:
    CONNECTION_COMPLETE = 0x01
    ADVERTISING_REPORT = 0x02
    LTK_REQUEST = 0x05
    ENHANCED_CONNECTION_COMPLETE = 0x0A


STATUS_NAMES = {
    0x00: "Success", 0x01: "Unknown HCI Command", 0x02: "Unknown Connection Identifier",
    0x03: "Hardware Failure", 0x04: "Page Timeout", 0x05: "Authentication Failure",
    0x06: "PIN or Key Missing", 0x08: "Connection Timeout", 0x0C: "Command Disallowed", 0x11: "Unsupported Feature",
    0x12: "Invalid HCI Command Parameters", 0x13: "Remote User Terminated Connection",
    0x16: "Connection Terminated By Local Host", 0x1F: "Unspecified Error",
    0x3D: "Connection Terminated due to MIC Failure", 0x3E: "Connection Failed to be Established",
}


class HciError(Exception):
    def __init__(self, op: int, status: int, what: str = ""):
        self.op, self.status = op, status
        super().__init__(f"HCI cmd 0x{op:04x} failed: status 0x{status:02x} "
                         f"({STATUS_NAMES.get(status, '?')}) {what}".strip())


class HciTimeout(TransportError):
    pass


# --------------------------------------------------------------------- utils
def bdaddr_str(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in reversed(b))


def bdaddr_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in reversed(s.split(":")))


def build_command(op: int, params: bytes = b"") -> bytes:
    if len(params) > 255:
        raise ValueError("HCI command params > 255 bytes")
    return struct.pack("<HB", op, len(params)) + params


# --------------------------------------------------------------------- events
@dataclass
class Event:
    code: int
    params: bytes
    fields: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        for k, v in vars(EVT).items():
            if v == self.code and not k.startswith("_"):
                return k
        return f"EVT_0x{self.code:02x}"


def parse_ad(data: bytes) -> list[tuple[int, bytes]]:
    """Advertising / EIR data -> [(ad_type, value)]."""
    out, i = [], 0
    while i < len(data):
        ln = data[i]
        if ln == 0 or i + 1 + ln > len(data):
            break
        out.append((data[i + 1], bytes(data[i + 2:i + 1 + ln])))
        i += 1 + ln
    return out


def ad_summary(ad: list[tuple[int, bytes]]) -> dict:
    s: dict = {}
    for t, v in ad:
        if t in (0x08, 0x09):
            s["name"] = v.decode("utf-8", "replace")
        elif t == 0x01 and v:
            s["flags"] = v[0]
        elif t in (0x02, 0x03):
            s.setdefault("uuid16", []).extend(f"{u:04x}" for u in struct.unpack(f"<{len(v)//2}H", v[: len(v) // 2 * 2]))
        elif t in (0x06, 0x07):
            s.setdefault("uuid128", []).extend(v[i:i + 16][::-1].hex() for i in range(0, len(v) - 15, 16))
        elif t == 0x0A and v:
            s["tx_power"] = struct.unpack("b", v[:1])[0]
        elif t == 0xFF and len(v) >= 2:
            s.setdefault("mfg", []).append((struct.unpack("<H", v[:2])[0], v[2:].hex()))
    return s


def _parse_adv_reports(p: bytes) -> list[dict]:
    n, i, out = p[0], 1, []
    for _ in range(n):
        if i + 9 > len(p):
            raise ValueError("truncated advertising report")
        etype, atype = p[i], p[i + 1]
        addr = p[i + 2:i + 8]
        dlen = p[i + 8]
        data = p[i + 9:i + 9 + dlen]
        if i + 9 + dlen + 1 > len(p):
            raise ValueError("truncated advertising report data")
        if i + 10 + dlen > len(p):
            break
        rssi = struct.unpack("b", p[i + 9 + dlen:i + 10 + dlen])[0]
        try:
            ad = parse_ad(data)
            summary = ad_summary(ad)
        except Exception:
            ad, summary = {}, {}
        out.append(dict(event_type=etype, addr_type=atype, addr=bdaddr_str(addr),
                        data=bytes(data), rssi=rssi, ad=ad, **summary))
        i += 10 + dlen
    return out


def _parse_ext_adv_reports(p: bytes) -> list[dict]:
    if not p:
        return []
    n, i, out = p[0], 1, []
    for _ in range(n):
        if i + 24 > len(p):
            break
        etype = struct.unpack_from("<H", p, i)[0]
        atype = p[i + 2]
        addr = p[i + 3:i + 9]
        pphy, sphy, sid, txp, rssi = p[i + 9], p[i + 10], p[i + 11], p[i + 12], p[i + 13]
        i += 14 + 2 + 1 + 6  # periodic interval + direct addr type + direct addr
        if i >= len(p):
            break
        dlen = p[i]; i += 1
        data = p[i:i + dlen]; i += dlen
        try:
            ad = parse_ad(data); summary = ad_summary(ad)
        except Exception:
            ad, summary = {}, {}
        out.append(dict(event_type=etype, addr_type=atype, addr=bdaddr_str(addr),
                        primary_phy=pphy, secondary_phy=sphy, sid=sid, tx_power=txp,
                        rssi=struct.unpack("b", bytes([rssi]))[0], data=bytes(data), ad=ad,
                        **summary))
    return out


def parse_event(pkt: bytes) -> Event:
    if len(pkt) < 2 or len(pkt) != 2 + pkt[1]:
        raise ValueError(f"bad event length: {pkt.hex()}")
    code, p = pkt[0], bytes(pkt[2:])
    ev = Event(code, p)
    f = ev.fields
    if code == EVT.COMMAND_COMPLETE:
        f["ncmd"], f["opcode"] = p[0], struct.unpack_from("<H", p, 1)[0]
        f["ret"] = p[3:]
        f["status"] = p[3] if len(p) > 3 else None
    elif code == EVT.COMMAND_STATUS:
        f["status"], f["ncmd"], f["opcode"] = p[0], p[1], struct.unpack_from("<H", p, 2)[0]
    elif code == EVT.INQUIRY_COMPLETE:
        f["status"] = p[0]
    elif code in (EVT.INQUIRY_RESULT, EVT.INQUIRY_RESULT_RSSI):
        n, res = p[0], []
        for k in range(n):
            e = p[1 + 14 * k:1 + 14 * (k + 1)]
            r = dict(addr=bdaddr_str(e[0:6]), pscan_rep_mode=e[6])
            if code == EVT.INQUIRY_RESULT:
                r.update(cod=int.from_bytes(e[9:12], "little"),
                         clock_offset=struct.unpack_from("<H", e, 12)[0])
            else:
                r.update(cod=int.from_bytes(e[8:11], "little"),
                         clock_offset=struct.unpack_from("<H", e, 11)[0],
                         rssi=struct.unpack_from("b", e, 13)[0])
            res.append(r)
        f["results"] = res
    elif code == EVT.EXTENDED_INQUIRY_RESULT:
        eir = parse_ad(p[15:])
        f["results"] = [dict(addr=bdaddr_str(p[1:7]), pscan_rep_mode=p[7],
                             cod=int.from_bytes(p[9:12], "little"),
                             clock_offset=struct.unpack_from("<H", p, 12)[0],
                             rssi=struct.unpack_from("b", p, 14)[0], ad=eir, **ad_summary(eir))]
    elif code == EVT.CONNECTION_COMPLETE:
        f.update(status=p[0], handle=struct.unpack_from("<H", p, 1)[0] & 0x0FFF,
                 addr=bdaddr_str(p[3:9]), link_type=p[9], encryption=p[10])
    elif code == EVT.CONNECTION_REQUEST:
        f.update(addr=bdaddr_str(p[0:6]), cod=int.from_bytes(p[6:9], "little"), link_type=p[9])
    elif code == EVT.DISCONNECTION_COMPLETE:
        f.update(status=p[0], handle=struct.unpack_from("<H", p, 1)[0] & 0x0FFF, reason=p[3])
    elif code == EVT.ENCRYPTION_CHANGE and len(p) >= 4:
        f.update(status=p[0], handle=struct.unpack_from("<H", p, 1)[0] & 0x0FFF, enabled=p[3])
    elif code == EVT.ENCRYPTION_KEY_REFRESH_COMPLETE and len(p) >= 3:
        f.update(status=p[0], handle=struct.unpack_from("<H", p, 1)[0] & 0x0FFF)
    elif code == EVT.NUM_COMPLETED_PACKETS:
        n = p[0]
        f["completed"] = [struct.unpack_from("<HH", p, 1 + 4 * k) for k in range(n)]
    elif code == EVT.HARDWARE_ERROR:
        f["hw_code"] = p[0]
    elif code == EVT.LE_META:
        sub = p[0]
        f["subevent"] = sub
        if sub == LE_SUB.ADVERTISING_REPORT:
            f["reports"] = _parse_adv_reports(p[1:])
        elif sub in (LE_SUB.CONNECTION_COMPLETE, 0x0A) and len(p) >= 12:
            f["status"] = p[1]
            f["handle"] = struct.unpack_from("<H", p, 2)[0]
            f["role"] = p[4]
            f["peer_addr_type"] = p[5]
            f["peer_addr"] = bdaddr_str(p[6:12])
        elif sub == 0x0D:
            f["ext_reports"] = _parse_ext_adv_reports(p[1:])
        elif sub in (LE_SUB.CONNECTION_COMPLETE, LE_SUB.ENHANCED_CONNECTION_COMPLETE):
            f.update(status=p[1], handle=struct.unpack_from("<H", p, 2)[0] & 0x0FFF,
                     role=p[4], peer_addr_type=p[5], peer_addr=bdaddr_str(p[6:12]))
            off = 12 + (12 if sub == LE_SUB.ENHANCED_CONNECTION_COMPLETE else 0)
            f["interval"], f["latency"], f["timeout"] = struct.unpack_from("<HHH", p, off)
        elif sub == LE_SUB.LTK_REQUEST and len(p) >= 13:
            f.update(handle=struct.unpack_from("<H", p, 1)[0] & 0x0FFF, rand=bytes(p[3:11]),
                     ediv=struct.unpack_from("<H", p, 11)[0])
    return ev


# --------------------------------------------------------------------- controller
@dataclass
class LocalVersion:
    hci_ver: int
    hci_rev: int
    lmp_ver: int
    manufacturer: int
    lmp_subver: int


@dataclass
class BufferSize:
    acl_len: int
    sco_len: int
    acl_num: int
    sco_num: int


class Hci:
    """Synchronous HCI host. Single-threaded: call pump() to process async input."""

    def __init__(self, transport: Transport, *, cmd_timeout_s: float = 6.0):
        self.t = transport
        self.cmd_timeout_s = cmd_timeout_s
        self.ncmd = 1  # Num_HCI_Command_Packets credit
        self.pending_events: list[Event] = []
        self.handlers: list[Callable[[Event], None]] = []
        self.acl_handlers: list[Callable[[bytes], None]] = []
        self.acl_credits: Optional[int] = None
        self.acl_mtu = 0
        self.le_acl_credits: Optional[int] = None
        self.le_acl_mtu = 0
        self.inflight: dict[int, int] = {}  # handle -> packets in flight
        self.le_handles: set[int] = set()
        self.le_conns: dict[int, dict] = {}  # handle -> role, peer_addr, peer_addr_type
        self.bd_addr: Optional[str] = None   # local public address (after read_bd_addr)
        self.tick_handlers: list[Callable[[], None]] = []  # run at the end of every pump()
        self.trace: list[tuple[str, bytes]] = []

    # -------- raw
    def _dispatch(self, ev: Event) -> None:
        if ev.code in (EVT.COMMAND_COMPLETE, EVT.COMMAND_STATUS):
            self.ncmd = ev.fields["ncmd"]
        if ev.code == EVT.NUM_COMPLETED_PACKETS:
            for h, n in ev.fields["completed"]:
                h &= 0x0FFF
                self.inflight[h] = max(0, self.inflight.get(h, 0) - n)
                if h in self.le_handles and self.le_acl_credits is not None:
                    self.le_acl_credits += n
                elif self.acl_credits is not None:
                    self.acl_credits += n
        if ev.code == EVT.LE_META and ev.fields.get("subevent") in (
                LE_SUB.CONNECTION_COMPLETE, LE_SUB.ENHANCED_CONNECTION_COMPLETE) \
                and ev.fields.get("status") == 0:
            self.le_handles.add(ev.fields["handle"])
            self.le_conns[ev.fields["handle"]] = {k: ev.fields[k] for k in (
                "role", "peer_addr", "peer_addr_type")}
        if ev.code == EVT.DISCONNECTION_COMPLETE:
            self.le_handles.discard(ev.fields.get("handle"))
            self.le_conns.pop(ev.fields.get("handle"), None)
        if ev.code == EVT.HARDWARE_ERROR:
            log.error("controller hardware error 0x%02x", ev.fields["hw_code"])
        for h in self.handlers:
            h(ev)

    def read_event(self, timeout_ms: int) -> Optional[Event]:
        raw = self.t.read_event(timeout_ms)
        if raw is None:
            return None
        self.trace.append(("evt", raw))
        log.debug("< evt %s", raw.hex())
        ev = parse_event(raw)
        self._dispatch(ev)
        return ev

    def pump(self, timeout_ms: int = 50) -> list[Event]:
        """Read pending events and ACL; return non-command events (also queued ones)."""
        out, self.pending_events = self.pending_events, []
        ev = self.read_event(timeout_ms)
        while ev is not None:
            out.append(ev)
            ev = self.read_event(1)
        acl = self.t.read_acl(1)
        while acl is not None:
            self.trace.append(("acl<", acl))
            for h in self.acl_handlers:
                h(acl)
            acl = self.t.read_acl(1)
        for t in list(self.tick_handlers):
            t()
        return out

    def send_raw_command(self, op: int, params: bytes = b"") -> None:
        pkt = build_command(op, params)
        self.trace.append(("cmd", pkt))
        log.debug("> cmd %s", pkt.hex())
        self.t.send_command(pkt)

    def command(self, op: int, params: bytes = b"", *, expect_status: bool = False,
                check: bool = True, timeout_s: Optional[float] = None) -> Event:
        """Send a command and wait for its Command Complete (or Command Status)."""
        deadline = time.monotonic() + (timeout_s or self.cmd_timeout_s)
        while self.ncmd == 0:  # flow control: wait for credit
            if time.monotonic() > deadline:
                raise HciTimeout(f"no command credit for 0x{op:04x}")
            ev = self.read_event(50)
            if ev is not None and ev.code not in (EVT.COMMAND_COMPLETE, EVT.COMMAND_STATUS):
                self.pending_events.append(ev)
        self.send_raw_command(op, params)
        self.ncmd = max(0, self.ncmd - 1)
        while True:
            remain = int((deadline - time.monotonic()) * 1000)
            if remain <= 0:
                raise HciTimeout(f"timeout waiting for completion of 0x{op:04x}")
            ev = self.read_event(min(remain, 200))
            if ev is None:
                continue
            if ev.code in (EVT.COMMAND_COMPLETE, EVT.COMMAND_STATUS) and ev.fields["opcode"] == op:
                st = ev.fields["status"]
                if check and st not in (None, 0):
                    raise HciError(op, st)
                if ev.code == EVT.COMMAND_STATUS and not expect_status:
                    log.debug("0x%04x answered with Command Status", op)
                return ev
            if ev.code in (EVT.COMMAND_COMPLETE, EVT.COMMAND_STATUS) and ev.fields["opcode"] == 0:
                continue  # NOP credit update (e.g. after reset)
            self.pending_events.append(ev)

    def wait_for(self, pred: Callable[[Event], bool], timeout_s: float) -> Optional[Event]:
        for i, ev in enumerate(self.pending_events):
            if pred(ev):
                return self.pending_events.pop(i)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            ev = self.read_event(100)
            if ev is None:
                continue
            if pred(ev):
                return ev
            self.pending_events.append(ev)
        return None

    # -------- standard commands
    def reset(self) -> None:
        self.command(OP.RESET, timeout_s=5.0)
        self.ncmd = 1

    def read_local_version(self) -> LocalVersion:
        r = self.command(OP.READ_LOCAL_VERSION).fields["ret"]
        _, hv, hr, lv, mf, ls = struct.unpack("<BBHBHH", r[:9])
        return LocalVersion(hv, hr, lv, mf, ls)

    def read_bd_addr(self) -> str:
        self.bd_addr = bdaddr_str(self.command(OP.READ_BD_ADDR).fields["ret"][1:7])
        return self.bd_addr

    def read_buffer_size(self) -> BufferSize:
        r = self.command(OP.READ_BUFFER_SIZE).fields["ret"]
        _, al, sl, an, sn = struct.unpack("<BHBHH", r[:8])
        self.acl_mtu, self.acl_credits = al, an
        return BufferSize(al, sl, an, sn)

    def le_read_buffer_size(self) -> tuple[int, int]:
        r = self.command(OP.LE_READ_BUFFER_SIZE).fields["ret"]
        _, ln, num = struct.unpack("<BHB", r[:4])
        if ln == 0:  # shared with BR/EDR buffers
            self.le_acl_mtu, self.le_acl_credits = self.acl_mtu, None
        else:
            self.le_acl_mtu, self.le_acl_credits = ln, num
        return ln, num

    def read_local_name(self) -> str:
        r = self.command(OP.READ_LOCAL_NAME).fields["ret"][1:]
        return r.split(b"\0", 1)[0].decode("utf-8", "replace")

    def set_event_mask(self, mask: int = 0x3DBFF807FFFBFFFF) -> None:
        self.command(OP.SET_EVENT_MASK, struct.pack("<Q", mask))

    def le_set_event_mask(self, mask: int = 0x000000000000021F) -> None:
        self.command(OP.LE_SET_EVENT_MASK, struct.pack("<Q", mask))

    def write_le_host_supported(self, on: bool = True) -> None:
        self.command(OP.WRITE_LE_HOST_SUPPORTED, bytes([1 if on else 0, 0]))

    def write_inquiry_mode(self, mode: int = 2) -> None:  # 2 = extended (EIR)
        self.command(OP.WRITE_INQUIRY_MODE, bytes([mode]))

    def write_scan_enable(self, v: int) -> None:  # 0 none, 1 inq, 2 page, 3 both
        self.command(OP.WRITE_SCAN_ENABLE, bytes([v]))

    def le_set_scan_parameters(self, active: bool = True, interval: int = 0x0060,
                               window: int = 0x0030, own_addr_type: int = 0,
                               filter_policy: int = 0) -> None:
        self.command(OP.LE_SET_SCAN_PARAMETERS, struct.pack(
            "<BHHBB", 1 if active else 0, interval, window, own_addr_type, filter_policy))

    def le_set_scan_enable(self, enable: bool, filter_dup: bool = True) -> None:
        self.command(OP.LE_SET_SCAN_ENABLE, bytes([int(enable), int(filter_dup)]))

    def le_enable_all_events(self) -> None:
        # LE Set Event Mask: enable all LE Meta events (incl. advertising reports)
        self.command(OP.LE_SET_EVENT_MASK, struct.pack("<Q", 0x0000000000001FFF))

    def le_create_connection(self, addr: str, timeout: float = 10.0,
                             interval: int = 0x0060, window: int = 0x0030,
                             conn_min: int = 0x0018, conn_max: int = 0x0028,
                             latency: int = 0, supervision: int = 0x0190) -> int:
        """LE Create Connection (0x200D). Returns the connection handle."""
        raw = bytes(int(x, 16) for x in reversed(addr.split(":")))
        self.le_enable_all_events()
        params = struct.pack("<HHBB6sBHHHHHH", interval, window, 0x00, 0x00, raw, 0x00,
                             conn_min, conn_max, latency, supervision, 0x0000, 0x0000)
        self.command(OP.LE_CREATE_CONNECTION, params, expect_status=True)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for ev in self.pump(100):
                if ev.code == EVT.LE_META and ev.fields.get("subevent") in (LE_SUB.CONNECTION_COMPLETE, 0x0A):
                    f = ev.fields
                    if f.get("status") not in (0, None):
                        raise HciError(OP.LE_CREATE_CONNECTION, f["status"], "LE connection failed")
                    handle = f.get("handle")
                    if handle is not None:
                        self.le_handles.add(handle)
                        self.le_conns[handle] = {
                            "role": f.get("role", 0),
                            "peer_addr": f.get("peer_addr", ""),
                            "peer_addr_type": f.get("peer_addr_type", 0),
                        }
                        return handle
        raise HciTimeout(OP.LE_CREATE_CONNECTION, "LE connection timeout")

    def le_set_ext_scan_parameters(self, phys: int = 0x05, active: bool = True,
                                   interval: int = 0x0030, window: int = 0x0030) -> None:
        body = bytes([0, 0, phys])
        for bit in (0x01, 0x04):
            if phys & bit:
                body += struct.pack("<BHH", 1 if active else 0, interval, window)
        self.command(OP.LE_SET_EXT_SCAN_PARAMETERS, body)

    def le_set_ext_scan_enable(self, enable: bool, filter_dup: bool = False) -> None:
        self.command(OP.LE_SET_EXT_SCAN_ENABLE,
                     struct.pack("<BBHH", int(enable), int(filter_dup), 0, 0))

    def le_scan_ext(self, seconds: float) -> dict[str, dict]:
        self.le_enable_all_events()
        self.le_set_ext_scan_parameters()
        self.le_set_ext_scan_enable(True)
        seen: dict[str, dict] = {}
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                try:
                    events = self.pump(100)
                except Exception:
                    continue
                for ev in events:
                    if ev.code != EVT.LE_META:
                        continue
                    sub = ev.fields.get("subevent")
                    if sub == 0x0D:
                        for r in ev.fields.get("ext_reports", []):
                            seen.setdefault(r["addr"], {}).update(r)
                    elif sub == LE_SUB.ADVERTISING_REPORT:
                        for r in ev.fields.get("reports", []):
                            seen.setdefault(r["addr"], {}).update(r)
        finally:
            try:
                self.le_set_ext_scan_enable(False)
            except Exception:
                pass
        return seen

    def le_scan(self, seconds: float, active: bool = True) -> dict[str, dict]:
        """Run an LE scan; return {addr: last report}."""
        self.le_enable_all_events()
        self.le_set_scan_parameters(active=active)
        self.le_set_scan_enable(True, filter_dup=False)
        seen: dict[str, dict] = {}
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                try:
                    events = self.pump(100)
                except Exception:
                    continue
                for ev in events:
                    if ev.code == EVT.LE_META and ev.fields.get("subevent") == LE_SUB.ADVERTISING_REPORT:
                        for r in ev.fields["reports"]:
                            prev = seen.get(r["addr"], {})
                            prev.update({k: v for k, v in r.items() if v not in (None, b"")})
                            seen[r["addr"]] = prev
        finally:
            try:
                self.le_set_scan_enable(False, filter_dup=True)
            except Exception:
                pass
        return seen

    def inquiry(self, seconds: float = 5.12, lap: int = 0x9E8B33, max_resp: int = 0) -> dict[str, dict]:
        length = max(1, min(0x30, round(seconds / 1.28)))
        self.command(OP.INQUIRY, lap.to_bytes(3, "little") + bytes([length, max_resp]),
                     expect_status=True)
        found: dict[str, dict] = {}
        end = time.monotonic() + length * 1.28 + 2
        while time.monotonic() < end:
            for ev in self.pump(100):
                if ev.code in (EVT.INQUIRY_RESULT, EVT.INQUIRY_RESULT_RSSI, EVT.EXTENDED_INQUIRY_RESULT):
                    for r in ev.fields["results"]:
                        found.setdefault(r["addr"], {}).update(r)
                elif ev.code == EVT.INQUIRY_COMPLETE:
                    return found
        return found

    def disconnect(self, handle: int, reason: int = 0x13) -> None:
        self.command(OP.DISCONNECT, struct.pack("<HB", handle, reason), expect_status=True)

    def create_connection(self, addr: str, pkt_type: int = 0xCC18, allow_role_switch: bool = True) -> None:
        self.command(OP.CREATE_CONNECTION, bdaddr_bytes(addr) + struct.pack(
            "<HBBHB", pkt_type, 0x01, 0x00, 0x0000, int(allow_role_switch)), expect_status=True)

    # -------- LE security (used by smp.py; the SMP layer defers these to a tick so they are
    # never issued from inside an event handler)
    def le_start_encryption(self, handle: int, ltk: bytes, ediv: int = 0, rand: bytes = bytes(8)) -> Event:
        return self.command(OP.LE_START_ENCRYPTION, struct.pack("<H", handle) + bytes(rand)
                            + struct.pack("<H", ediv) + bytes(ltk), expect_status=True, check=False)

    def le_ltk_reply(self, handle: int, ltk: bytes) -> Event:
        return self.command(OP.LE_LTK_REQUEST_REPLY, struct.pack("<H", handle) + bytes(ltk), check=False)

    def le_ltk_neg_reply(self, handle: int) -> Event:
        return self.command(OP.LE_LTK_REQUEST_NEG_REPLY, struct.pack("<H", handle), check=False)

    # -------- ACL
    def send_acl_packet(self, pkt: bytes, handle: int) -> None:
        le = handle in self.le_handles and self.le_acl_credits is not None
        credits = self.le_acl_credits if le else self.acl_credits
        deadline = time.monotonic() + self.cmd_timeout_s
        while credits is not None and credits <= 0:
            if time.monotonic() > deadline:
                raise HciTimeout(f"no ACL buffer credit for handle 0x{handle:03x}")
            ev = self.read_event(50)
            if ev is not None:
                self.pending_events.append(ev)
            credits = self.le_acl_credits if le else self.acl_credits
        self.trace.append(("acl>", pkt))
        self.t.send_acl(pkt)
        self.inflight[handle] = self.inflight.get(handle, 0) + 1
        if le:
            self.le_acl_credits -= 1
        elif self.acl_credits is not None:
            self.acl_credits -= 1

    def init_standard(self) -> dict:
        """Typical bring-up after (optional) vendor firmware load."""
        self.reset()
        info: dict = {}
        info["version"] = self.read_local_version()
        info["bd_addr"] = self.read_bd_addr()
        info["buffer"] = self.read_buffer_size()
        self.set_event_mask()
        try:
            self.write_le_host_supported(True)
        except HciError as e:
            log.info("WRITE_LE_HOST_SUPPORTED: %s", e)
        try:
            info["le_buffer"] = self.le_read_buffer_size()
            self.le_set_event_mask()
        except HciError as e:
            log.info("LE not available: %s", e)
        return info
