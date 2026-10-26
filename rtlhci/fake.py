"""Software model of an RTL8761BU controller, for tests and dry runs.

FakeController  -- HCI-level behaviour (commands -> events, ACL loopback)
FakeTransport   -- Transport directly on top of FakeController
FakeUsbDevice   -- pyusb-Device look-alike (ctrl_transfer/read/write/...),
                   splits events into 16-byte interrupt packets, can inject
                   macOS-style detach/claim failures.
"""
from __future__ import annotations

import struct
from typing import Optional

from .acl import CID_SMP, L2capReassembler, build_acl, build_l2cap, parse_acl
from .btsnoop import H4_ACL, H4_CMD, H4_EVT
from .hci import EVT, OP, bdaddr_bytes
from .transport import Transport


def evt(code: int, params: bytes) -> bytes:
    return bytes([code, len(params)]) + params


def cc(op: int, ret: bytes, ncmd: int = 1) -> bytes:
    return evt(EVT.COMMAND_COMPLETE, bytes([ncmd]) + struct.pack("<H", op) + ret)


def cs(op: int, status: int = 0, ncmd: int = 1) -> bytes:
    return evt(EVT.COMMAND_STATUS, bytes([status, ncmd]) + struct.pack("<H", op))


class FakeController:
    def __init__(self, *, patched: bool = False, rom_version: int = 1, key_id: int = 0,
                 bdaddr: str = "E8:48:B8:C8:20:00", acl_mtu: int = 1021, acl_num: int = 6,
                 le_mtu: int = 251, le_num: int = 8, fail_ops: Optional[dict] = None):
        self.patched = patched
        self.rom_version, self.key_id, self.bdaddr = rom_version, key_id, bdaddr
        self.acl_mtu, self.acl_num, self.le_mtu, self.le_num = acl_mtu, acl_num, le_mtu, le_num
        self.fail_ops = fail_ops or {}
        self.events: list[bytes] = []
        self.acl_out: list[bytes] = []   # controller -> host
        self.acl_in: list[bytes] = []    # host -> controller
        self.cmds: list[bytes] = []
        self.dl_frags: list[bytes] = []
        self.dl_data = bytearray()
        self.scanning = False
        self.adv_reports: list[bytes] = []
        self.inquiry_results: list[bytes] = []
        self.echo_acl = False
        self.drop_count = 0
        self.peers: dict[int, "FakeSmpPeer"] = {}   # handle -> remote SMP device
        self._peer_rx = L2capReassembler(self._peer_frame)
        self.peer_enc: dict[int, tuple] = {}         # handle -> (ltk, ediv, rand) from peer central
        self.encrypted: dict[int, bytes] = {}        # handle -> LTK in use on the "link"

    # ---------------- host -> controller
    def on_command(self, pkt: bytes) -> None:
        self.cmds.append(pkt)
        op, plen = struct.unpack_from("<HB", pkt)
        p = pkt[3:]
        assert len(p) == plen, "plen mismatch"
        if op in self.fail_ops:
            self.events.append(cc(op, bytes([self.fail_ops[op]])))
            return
        h = getattr(self, f"_op_{op:04x}", None)
        if h is None:
            self.events.append(cc(op, b"\x01"))  # Unknown HCI Command
            return
        h(op, p)

    def on_acl(self, pkt: bytes) -> None:
        self.acl_in.append(pkt)
        a = parse_acl(pkt)
        self.events.append(evt(EVT.NUM_COMPLETED_PACKETS, b"\x01" + struct.pack("<HH", a.handle, 1)))
        if self.echo_acl:
            self.acl_out.append(pkt)
        if a.handle in self.peers:
            self._peer_rx.feed(pkt)

    def _peer_frame(self, handle: int, cid: int, payload: bytes) -> None:
        self.peers[handle].on_l2cap(cid, payload)

    def attach_peer(self, peer: "FakeSmpPeer") -> None:
        self.peers[peer.handle] = peer

    # ---------------- standard commands
    def _ok(self, op, extra=b""):
        self.events.append(cc(op, b"\x00" + extra))

    def _op_0c03(self, op, p):  # reset
        self.scanning = False
        self._ok(op)

    def _op_1001(self, op, p):  # read local version
        if self.patched:
            # ASSUMPTION: Linux logs "fw version 0x%04x%04x" from (hci_rev, lmp_subver) right
            # after download; for rtl8761bu_fw that prints the epatch version 0xdfc6d922.
            hv, hr, lv, ls = 0x0A, 0xDFC6, 0x0A, 0xD922
        else:
            hv, hr, lv, ls = 0x0A, 0x000B, 0x0A, 0x8761
        self._ok(op, struct.pack("<BHBHH", hv, hr, lv, 93, ls))

    def _op_1009(self, op, p):
        self._ok(op, bdaddr_bytes(self.bdaddr))

    def _op_1005(self, op, p):
        self._ok(op, struct.pack("<HBHH", self.acl_mtu, 255, self.acl_num, 12))

    def _op_2002(self, op, p):
        self._ok(op, struct.pack("<HB", self.le_mtu, self.le_num))

    def _op_0c14(self, op, p):
        self._ok(op, b"RTL8761BU fake".ljust(248, b"\0"))

    _op_0c01 = _op_2001 = _op_0c6d = _op_0c45 = _op_0c1a = _op_0c13 = _ok_generic = (
        lambda self, op, p: self._ok(op))

    def _op_200b(self, op, p):
        assert len(p) == 7
        self._ok(op)

    def _op_200c(self, op, p):
        self.scanning = bool(p[0])
        self._ok(op)
        if self.scanning:
            for r in self.adv_reports:
                self.events.append(evt(EVT.LE_META, b"\x02" + r))

    def _op_0401(self, op, p):
        self.events.append(cs(op))
        for r in self.inquiry_results:
            self.events.append(r)
        self.events.append(evt(EVT.INQUIRY_COMPLETE, b"\x00"))

    def _op_0406(self, op, p):
        h, reason = struct.unpack("<HB", p)
        self.events.append(cs(op))
        self.events.append(evt(EVT.DISCONNECTION_COMPLETE, struct.pack("<BHB", 0, h, 0x16)))

    # ---------------- LE encryption, emulated between host and attached FakeSmpPeer
    def _enc_change(self, handle: int, status: int, enabled: int) -> None:
        self.events.append(evt(EVT.ENCRYPTION_CHANGE, struct.pack("<BHB", status, handle, enabled)))

    def _link_encrypt(self, handle: int, host_ltk, peer_ltk) -> None:
        peer = self.peers.get(handle)
        if host_ltk is None or peer_ltk is None:
            self._enc_change(handle, 0x06, 0)  # PIN or Key Missing
            ok = False
        elif host_ltk != peer_ltk:
            # LL would fail the encryption handshake (MIC failure) and drop the link
            self.events.append(evt(EVT.DISCONNECTION_COMPLETE, struct.pack("<BHB", 0, handle, 0x3D)))
            ok = False
        else:
            self.encrypted[handle] = host_ltk
            self._enc_change(handle, 0, 1)
            ok = True
        if peer is not None:
            peer.on_encrypted(ok)

    def _op_2019(self, op, p):  # LE Start Encryption (host is central)
        handle, = struct.unpack_from("<H", p)
        rand, ediv, ltk = p[2:10], struct.unpack_from("<H", p, 10)[0], p[12:28]
        self.events.append(cs(op))
        peer = self.peers.get(handle)
        peer_ltk = peer.on_ltk_request(ediv, rand) if peer else None
        self._link_encrypt(handle, ltk, peer_ltk)

    def peer_start_encryption(self, handle: int, ltk: bytes, ediv: int, rand: bytes) -> None:
        """Peer is central: controller raises LE LTK Request to the host."""
        self.peer_enc[handle] = (ltk, ediv, rand)
        self.events.append(evt(EVT.LE_META, struct.pack("<BH", 0x05, handle) + bytes(rand)
                               + struct.pack("<H", ediv)))

    def _op_201a(self, op, p):  # LTK Request Reply
        handle, = struct.unpack_from("<H", p)
        self._ok(op, struct.pack("<H", handle))
        want = self.peer_enc.pop(handle, (None,))[0]
        self._link_encrypt(handle, p[2:18], want)

    def _op_201b(self, op, p):  # LTK Request Negative Reply
        handle, = struct.unpack_from("<H", p)
        self._ok(op, struct.pack("<H", handle))
        self.peer_enc.pop(handle, None)
        self._link_encrypt(handle, None, None)

    # ---------------- Realtek vendor
    def _op_fc61(self, op, p):
        if p == bytes([0x10, 0x38, 0x04, 0x28, 0x80]):
            self._ok(op, struct.pack("<H", 0x8761))
        elif p == bytes([0x10, 0xA4, 0xAD, 0x00, 0xB0]):
            self._ok(op, bytes([self.key_id, 0]))
        else:
            self._ok(op, b"\x00\x00")

    def _op_fc6d(self, op, p):
        self._ok(op, bytes([self.rom_version]))

    def _op_fc66(self, op, p):  # drop fw: back to ROM, no completion event (like real HW)
        self.drop_count += 1
        if self.patched != "sticky":
            self.patched = False

    def _op_fc20(self, op, p):
        idx = p[0]
        self.dl_frags.append(p)
        self.dl_data += p[1:]
        self._ok(op, bytes([idx]))
        if idx & 0x80:
            self.patched = True

    # ---------------- controller-originated helpers
    def connect_le(self, handle: int, peer: str = "11:22:33:44:55:66", role: int = 0,
                   peer_addr_type: int = 0) -> None:
        """role is the *host's* role: 0 central, 1 peripheral."""
        self.events.append(evt(EVT.LE_META, struct.pack("<BBHBB", 0x01, 0, handle, role, peer_addr_type)
                               + bdaddr_bytes(peer) + struct.pack("<HHHB", 24, 0, 500, 0)))

    def connect_bredr(self, handle: int, peer: str = "AA:BB:CC:DD:EE:FF") -> None:
        self.events.append(evt(EVT.CONNECTION_COMPLETE, struct.pack("<BH", 0, handle)
                               + bdaddr_bytes(peer) + b"\x01\x00"))

    def send_l2cap(self, handle: int, cid: int, payload: bytes, frag: int = 27, pb_first: int = 0b10):
        frame = build_l2cap(cid, payload)
        for off in range(0, len(frame), frag):
            self.acl_out.append(build_acl(handle, pb_first if off == 0 else 0b01, frame[off:off + frag]))


class FakeTransport(Transport):
    def __init__(self, ctl: FakeController, snoop=None):
        self.ctl = ctl
        self.snoop = snoop

    def send_command(self, pkt):
        self.ctl.on_command(bytes(pkt))
        self._snoop(H4_CMD, pkt, False)

    def read_event(self, timeout_ms):
        if not self.ctl.events:
            return None
        p = self.ctl.events.pop(0)
        self._snoop(H4_EVT, p, True)
        return p

    def send_acl(self, pkt):
        self._snoop(H4_ACL, pkt, False)  # before delivery: the peer may answer synchronously
        self.ctl.on_acl(bytes(pkt))

    def read_acl(self, timeout_ms):
        if not self.ctl.acl_out:
            return None
        p = self.ctl.acl_out.pop(0)
        self._snoop(H4_ACL, p, True)
        return p


# ---------------------------------------------------------------- pyusb fakes
class FakeUSBError(IOError):
    def __init__(self, strerror, error_code=None, errno=None):
        IOError.__init__(self, errno, strerror)
        self.backend_error_code = error_code


class USBTimeoutError(FakeUSBError):
    pass


class _Ep:
    def __init__(self, addr, attr, mps):
        self.bEndpointAddress, self.bmAttributes, self.wMaxPacketSize = addr, attr, mps


class _Cfg:
    def __init__(self):
        self.intf0 = [_Ep(0x81, 3, 16), _Ep(0x02, 2, 64), _Ep(0x82, 2, 64)]

    def __getitem__(self, key):
        if key == (0, 0):
            return self.intf0
        raise KeyError(key)


class FakeUsbUtil:
    def __init__(self, claim_error: Optional[FakeUSBError] = None):
        self.claim_error, self.claimed, self.released = claim_error, [], []

    def claim_interface(self, dev, i):
        if self.claim_error:
            raise self.claim_error
        self.claimed.append(i)

    def release_interface(self, dev, i):
        self.released.append(i)

    def dispose_resources(self, dev):
        pass


class FakeUsbDevice:
    idVendor, idProduct = 0x2357, 0x0604
    bDeviceClass, bDeviceSubClass, bDeviceProtocol = 0xE0, 0x01, 0x01

    def __init__(self, ctl: FakeController, *, kernel_driver: bool = False,
                 detach_error: Optional[FakeUSBError] = None, kda_error: Optional[FakeUSBError] = None,
                 configured: bool = True):
        self.ctl = ctl
        self.kernel_driver, self.detach_error, self.kda_error = kernel_driver, detach_error, kda_error
        self.configured = configured
        self.ctrl_log = []
        self._intr = bytearray()
        self._bulk = bytearray()
        self.detached = []

    def is_kernel_driver_active(self, i):
        if self.kda_error:
            raise self.kda_error
        return self.kernel_driver and i == 0

    def detach_kernel_driver(self, i):
        if self.detach_error:
            raise self.detach_error
        self.detached.append(i)

    def attach_kernel_driver(self, i):
        pass

    def get_active_configuration(self):
        if not self.configured:
            raise FakeUSBError("Configuration not set", -5)
        return _Cfg()

    def set_configuration(self):
        self.configured = True

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data, timeout):
        self.ctrl_log.append((bmRequestType, bRequest, wValue, wIndex))
        assert (bmRequestType, bRequest, wValue, wIndex) == (0x20, 0, 0, 0)
        self.ctl.on_command(bytes(data))
        return len(data)

    def read(self, ep, size, timeout):
        if ep == 0x81:
            # emulate interrupt EP with 16-byte max packet: one packet per read
            if not self._intr and self.ctl.events:
                self._intr += self.ctl.events.pop(0)
            if not self._intr:
                raise USBTimeoutError("Operation timed out", -7, 110)
            chunk = bytes(self._intr[:16])
            del self._intr[:16]
            return chunk
        if ep == 0x82:
            # bulk EP with 64-byte max packet, one packet per read (exercises reassembly)
            if not self._bulk and self.ctl.acl_out:
                self._bulk += self.ctl.acl_out.pop(0)
            if not self._bulk:
                raise USBTimeoutError("Operation timed out", -7, 110)
            chunk = bytes(self._bulk[:64])
            del self._bulk[:64]
            return chunk
        raise FakeUSBError("bad ep", -2)

    def write(self, ep, data, timeout):
        assert ep == 0x02
        self.ctl.on_acl(bytes(data))
        return len(data)


# ---------------------------------------------------------------- fake SMP peer
class FakeSmpPeer:
    """Remote LE device speaking SMP, written independently of rtlhci.smp (it only shares the
    crypto toolbox, which is pinned by the spec sample data). Plays initiator (the peer is
    central, host is peripheral) or responder. Fault knobs drive the failure tests.

    passkey: for the peer's *input* side, a callable returning the passkey the user typed
    (e.g. reading what the host displayed); when the peer displays, it generates one and
    stores it in `displayed_passkey`.
    """

    def __init__(self, ctl: FakeController, handle: int, *, initiator: bool,
                 addr: str = "11:22:33:44:55:66", addr_type: int = 0, io: int = 3,
                 auth: int = 0x09, max_key: int = 16, ikd: int = 0x07, rkd: int = 0x07,
                 oob: int = 0, passkey=None, nc_accept: bool = True, rng=None,
                 corrupt_confirm: bool = False, corrupt_dhkey_check: bool = False,
                 bad_public_key: bool = False, reflect_public_key: bool = False,
                 f4_xcross: bool = False, silent_on: tuple = (), mutate=None):
        import os as _os
        from . import smp_crypto as C
        self.C = C
        self.ctl, self.handle, self.initiator = ctl, handle, initiator
        self.addr, self.addr_type = bdaddr_bytes(addr), addr_type
        self.io, self.auth, self.max_key, self.ikd, self.rkd, self.oob = io, auth, max_key, ikd, rkd, oob
        self.passkey_src, self.nc_accept = passkey, nc_accept
        self.rng = rng or _os.urandom
        self.corrupt_confirm, self.corrupt_dhkey_check = corrupt_confirm, corrupt_dhkey_check
        self.bad_public_key, self.reflect_public_key = bad_public_key, reflect_public_key
        self.f4_xcross = f4_xcross
        self.silent_on, self.mutate = set(silent_on), mutate
        self.rx: list[bytes] = []
        self.tx: list[bytes] = []
        self.host_failed: Optional[int] = None   # reason the host sent us
        self.sent_failed: Optional[int] = None   # reason we sent
        self.silent = False
        self.done = False
        self.encrypted = False
        self.ltk: Optional[bytes] = None           # STK/LTK used for encryption
        self.dist_ltk = None                       # legacy LTK we distributed (ltk, ediv, rand)
        self.keys_from_host: dict[int, bytes] = {}
        self.displayed_passkey: Optional[int] = None
        self.nc_value: Optional[int] = None
        self.preq = self.pres = b""
        self.round = 0
        self.pending: list[int] = []
        self.ctl.attach_peer(self)

    # -------------------------------------------------------------- plumbing
    @property
    def host_addr(self) -> bytes:
        return bdaddr_bytes(self.ctl.bdaddr)

    def send(self, pdu: bytes) -> None:
        if self.mutate:
            pdu = self.mutate(pdu)
            if pdu is None:
                return
        self.tx.append(pdu)
        self.ctl.send_l2cap(self.handle, CID_SMP, pdu, frag=27, pb_first=0b00)

    def inject(self, pdu: bytes) -> None:
        """Send an arbitrary SMP PDU (bypasses mutate)."""
        self.tx.append(pdu)
        self.ctl.send_l2cap(self.handle, CID_SMP, pdu, frag=27, pb_first=0b00)

    def fail(self, reason: int) -> None:
        self.sent_failed = reason
        self.send(bytes([0x05, reason]))
        self.silent = True

    def start(self) -> None:
        """Initiator: send Pairing Request."""
        self.preq = bytes([0x01, self.io, self.oob, self.auth, self.max_key, self.ikd, self.rkd])
        self.send(self.preq)

    def _rand(self, n: int) -> bytes:
        return bytes(self.rng(n))

    # -------------------------------------------------------------- method selection
    @staticmethod
    def method(init_io: int, resp_io: int, sc: bool, mitm: bool) -> tuple:
        """Independent re-derivation of Table 2.8 (rules, not a lookup table)."""
        if not mitm or 3 in (init_io, resp_io):
            return ("just_works", None)
        if sc and init_io in (1, 4) and resp_io in (1, 4):
            return ("numeric_comparison", None)
        if init_io == 2 and resp_io == 2:
            return ("passkey", "both_input")
        if init_io == 2 or (init_io == 4 and resp_io in (0, 1)):
            return ("passkey", "initiator_inputs")
        if resp_io == 2 or (resp_io == 4 and init_io in (0, 1, 4)):
            return ("passkey", "responder_inputs")
        return ("just_works", None)

    def _setup(self) -> None:
        q, r = self.preq, self.pres
        self.sc = bool(q[3] & r[3] & 0x08)
        self.key_size = min(q[4], r[4])
        self.m, self.pk_role = self.method(q[1], r[1], self.sc, bool((q[3] | r[3]) & 0x04))
        bond = bool(q[3] & r[3] & 0x01)
        drop = 0x09 if self.sc else 0x08
        self.dist_i = (q[5] & r[5] & ~drop) if bond else 0
        self.dist_r = (q[6] & r[6] & ~drop) if bond else 0
        self.passkey = None
        if self.m == "passkey":
            me_inputs = self.pk_role == "both_input" or \
                (self.pk_role == "initiator_inputs") == self.initiator
            if me_inputs:
                self.passkey = None   # typed by the "user" when first needed (lazy)
            else:
                self.displayed_passkey = self.passkey = int.from_bytes(self._rand(3), "little") % 1000000
        if self.initiator:
            self.ia, self.iat, self.ra, self.rat = self.addr, self.addr_type, self.host_addr, 0
        else:
            self.ia, self.iat, self.ra, self.rat = self.host_addr, 0, self.addr, self.addr_type

    def _pk(self) -> int:
        if self.passkey is None and self.m == "passkey":
            self.passkey = int(self.passkey_src()) if self.passkey_src else 0
        return self.passkey or 0

    def _tk(self) -> bytes:
        return self._pk().to_bytes(16, "little")

    def _c1(self, r: bytes) -> bytes:
        return self.C.c1(self._tk(), r, self.preq, self.pres, self.iat, self.ia, self.rat, self.ra)

    def _confirm(self, value: bytes) -> None:
        if self.corrupt_confirm:
            value = bytes([value[0] ^ 1]) + value[1:]
        self.send(bytes([0x03]) + value)

    # -------------------------------------------------------------- receive
    def on_l2cap(self, cid: int, pdu: bytes) -> None:
        if cid != CID_SMP:
            return
        self.rx.append(pdu)
        if pdu[:1] == b"\x05":
            self.host_failed = pdu[1] if len(pdu) > 1 else -1
            self.silent = True
            return
        if self.silent:
            return
        if pdu[:1] and pdu[0] in self.silent_on:
            self.silent = True
            return
        code = pdu[0]
        getattr(self, f"_rx_{code:02x}", self._rx_other)(pdu)

    def _rx_other(self, pdu: bytes) -> None:
        pass

    def _rx_0b(self, pdu: bytes) -> None:   # Security Request -> start pairing
        if self.initiator:
            self.start()

    def _rx_01(self, pdu: bytes) -> None:   # Pairing Request (we are responder)
        self.preq = pdu
        self.pres = bytes([0x02, self.io, self.oob, self.auth, self.max_key,
                           pdu[5] & self.ikd, pdu[6] & self.rkd])
        self.send(self.pres)
        self._setup()

    def _rx_02(self, pdu: bytes) -> None:   # Pairing Response (we are initiator)
        self.pres = pdu
        self._setup()
        if self.sc:
            self._send_pk()
        else:
            self.mrand = self._rand(16)
            self._confirm(self._c1(self.mrand))

    def _send_pk(self) -> None:
        self.priv, self.pub = self.C.generate_keypair(self.rng)
        pk = self.pub
        if self.bad_public_key:
            pk = pk[:32] + bytes([pk[32] ^ 1]) + pk[33:]
        if self.reflect_public_key and getattr(self, "peer_pub", None):
            pk = self.peer_pub
        self.send(bytes([0x0C]) + pk)

    def _rx_0c(self, pdu: bytes) -> None:   # Public Key
        self.peer_pub = pdu[1:]
        if not self.initiator:
            self._send_pk()
        try:
            self.dh = self.C.dhkey(self.priv, self.peer_pub)
        except self.C.InvalidPublicKey:
            return self.fail(0x0B)
        self.pka, self.pkb = (self.pub, self.peer_pub) if self.initiator else (self.peer_pub, self.pub)
        self.round = 0
        if self.m == "passkey":
            if self.initiator:
                self._pk_confirm()
        elif not self.initiator:
            self.nb = self._rand(16)
            self._confirm(self._f4conf(self.pkb, self.pka, self.nb, 0))

    def _f4conf(self, own: bytes, peer: bytes, rnd: bytes, z: int) -> bytes:
        """Confirm value; f4_xcross reproduces the peer quirk f4(own_x, peer_x, rnd, z)."""
        if self.f4_xcross:
            return self.C.f4(own[:32], peer[:32], rnd, z)
        return self.C.f4(own[:32], own[32:], rnd, z)

    def _ri(self) -> int:
        return 0x80 | ((self._pk() >> self.round) & 1)

    def _pk_confirm(self) -> None:
        if self.initiator:
            self.na = self._rand(16)
            self._confirm(self._f4conf(self.pka, self.pkb, self.na, self._ri()))
        else:
            self.nb = self._rand(16)
            self._confirm(self._f4conf(self.pkb, self.pka, self.nb, self._ri()))

    def _rx_03(self, pdu: bytes) -> None:   # Pairing Confirm
        self.rconf = pdu[1:]
        if not self.sc:
            if self.initiator:
                self.send(bytes([0x04]) + self.mrand)
            else:
                self.srand = self._rand(16)
                self._confirm(self._c1(self.srand))
        elif self.m == "passkey":
            if self.initiator:
                self.send(bytes([0x04]) + self.na)
            else:
                self._pk_confirm()
        else:   # JW/NC
            if self.initiator:   # got Cb -> send Na
                self.na = self._rand(16)
                self.send(bytes([0x04]) + self.na)
            # responder: just got Ca; it is verified when Na arrives.

    def _rx_04(self, pdu: bytes) -> None:   # Pairing Random
        n = pdu[1:]
        C = self.C
        if not self.sc:
            if self._c1(n) != self.rconf:
                return self.fail(0x04)
            if self.initiator:
                self.srand = n
                self.ltk = C.mask_key(C.s1(self._tk(), self.srand, self.mrand), self.key_size)
                self.ctl.peer_start_encryption(self.handle, self.ltk, 0, bytes(8))
            else:
                self.mrand = n
                self.ltk = C.mask_key(C.s1(self._tk(), self.srand, self.mrand), self.key_size)
                self.send(bytes([0x04]) + self.srand)
            return
        if self.m == "passkey":
            if self.initiator:
                if self._f4conf(self.pkb, self.pka, n, self._ri()) != self.rconf:
                    return self.fail(0x04)
                self.nb = n
            else:
                if self._f4conf(self.pka, self.pkb, n, self._ri()) != self.rconf:
                    return self.fail(0x04)
                self.na = n
                self.send(bytes([0x04]) + self.nb)
            self.round += 1
            if self.round < 20:
                if self.initiator:
                    self._pk_confirm()
                return
        elif self.initiator:
            if self._f4conf(self.pkb, self.pka, n, 0) != self.rconf:
                return self.fail(0x04)
            self.nb = n
        else:
            self.na = n
            self.send(bytes([0x04]) + self.nb)
        if self.m == "numeric_comparison":
            self.nc_value = C.g2(self.pka[:32], self.pkb[:32], self.na, self.nb)
            if not self.nc_accept:
                return self.fail(0x0C)
        a, b = self.ia + bytes([self.iat]), self.ra + bytes([self.rat])
        self.mackey, ltk = C.f5(self.dh, self.na, self.nb, a, b)
        self.ltk = C.mask_key(ltk, self.key_size)
        self.r = self._pk().to_bytes(16, "little") if self.m == "passkey" else bytes(16)
        self.ea = C.f6(self.mackey, self.na, self.nb, self.r, self.preq[1:4], a, b)
        self.eb = C.f6(self.mackey, self.nb, self.na, self.r, self.pres[1:4], b, a)
        if self.initiator:
            self._dhcheck(self.ea)

    def _dhcheck(self, v: bytes) -> None:
        if self.corrupt_dhkey_check:
            v = bytes([v[0] ^ 0x80]) + v[1:]
        self.send(bytes([0x0D]) + v)

    def _rx_0d(self, pdu: bytes) -> None:   # DHKey Check
        if self.initiator:
            if pdu[1:] != self.eb:
                return self.fail(0x0B)
            self.ctl.peer_start_encryption(self.handle, self.ltk, 0, bytes(8))
        else:
            if pdu[1:] != self.ea:
                return self.fail(0x0B)
            self._dhcheck(self.eb)

    # -------------------------------------------------------------- encryption / keys
    def on_ltk_request(self, ediv: int, rand: bytes) -> Optional[bytes]:
        if self.silent:
            return None
        if ediv == 0 and rand == bytes(8) and self.ltk is not None:
            return self.ltk
        if self.dist_ltk and (ediv, rand) == self.dist_ltk[1:]:
            return self.dist_ltk[0]
        return None

    def _want_from_host(self) -> list[int]:
        kd = self.dist_r if self.initiator else self.dist_i
        out = []
        if kd & 1 and not self.sc:
            out += [0x06, 0x07]
        if kd & 2:
            out += [0x08, 0x09]
        if kd & 4:
            out += [0x0A]
        return out

    def _send_keys(self) -> None:
        kd = self.dist_i if self.initiator else self.dist_r
        if kd & 1 and not self.sc:
            ltk = self.C.mask_key(self._rand(16), self.key_size)
            ediv, rand = int.from_bytes(self._rand(2), "little"), self._rand(8)
            self.dist_ltk = (ltk, ediv, rand)
            self.send(b"\x06" + ltk)
            self.send(b"\x07" + struct.pack("<H", ediv) + rand)
        if kd & 2:
            self.send(b"\x08" + self._rand(16))
            self.send(bytes([0x09, self.addr_type]) + self.addr)
        if kd & 4:
            self.send(b"\x0a" + self._rand(16))

    def on_encrypted(self, ok: bool) -> None:
        self.encrypted = ok
        if not ok or self.silent or self.done or getattr(self, "_kd_started", False):
            return   # re-encryption of a bonded link: no new key distribution
        self._kd_started = True
        self.pending = self._want_from_host()
        if not self.initiator:
            self._send_keys()
        self._check_done()

    def _check_done(self) -> None:
        if not self.pending:
            if self.initiator:
                self._send_keys()
            self.done = True

    def _rx_kd(self, pdu: bytes) -> None:
        if not self.pending or pdu[0] != self.pending[0]:
            return self.fail(0x08)
        self.keys_from_host[pdu[0]] = pdu[1:]
        self.pending.pop(0)
        self._check_done()

    _rx_06 = _rx_07 = _rx_08 = _rx_09 = _rx_0a = _rx_kd
