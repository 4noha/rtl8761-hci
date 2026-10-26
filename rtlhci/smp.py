"""Security Manager Protocol (Core Vol 3 Part H) over the fixed L2CAP channels.

LE SMP runs on CID 0x0006 (`acl.CID_SMP`). On BR/EDR SMP (CID 0x0007) every Pairing Request is
refused with Pairing Not Supported: there is no cross-transport key derivation yet.

Implemented:
  * Pairing Request/Response/Confirm/Random/Failed, Security Request, Public Key,
    DHKey Check, Keypress Notification, key distribution PDUs
  * LE legacy pairing: Just Works and Passkey Entry (c1 / s1), STK, then LTK+EDIV/Rand
  * LE Secure Connections: P-256 ECDH, f4/f5/f6/g2, Just Works, Numeric Comparison and
    Passkey Entry (20 rounds), with optional debug keys
  * key distribution in spec order (LTK, EDIV/Rand, IRK, identity address, CSRK)
  * encryption: HCI LE_Start_Encryption when central, LTK Request reply when peripheral
  * the 30 s SMP timer; after a timeout the link carries no more SMP traffic
  * strict checks: a wrong length, a reserved value or an out-of-order PDU makes us send
    Pairing Failed. No received PDU can raise out of the handler.
Not implemented: OOB data (an OOB request is answered with OOB Not Available), CTKD, signed
writes (we hand out the CSRK but never use it), RPA generation, Repeated Attempts back-off.

Threading: same single-thread model as Hci. PDUs are handled inside Hci.pump(); HCI
commands (start encryption, LTK reply) are queued and issued from a tick at the end of pump()
so we never nest Hci.command() inside an event handler.
"""
from __future__ import annotations

import logging
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import smp_crypto as C
from .acl import CID_BREDR_SMP, CID_SMP
from .hci import EVT, LE_SUB, Event, bdaddr_bytes

log = logging.getLogger("rtlhci.smp")


class CODE:
    PAIRING_REQUEST = 0x01
    PAIRING_RESPONSE = 0x02
    PAIRING_CONFIRM = 0x03
    PAIRING_RANDOM = 0x04
    PAIRING_FAILED = 0x05
    ENCRYPTION_INFO = 0x06
    CENTRAL_IDENT = 0x07
    IDENTITY_INFO = 0x08
    IDENTITY_ADDR_INFO = 0x09
    SIGNING_INFO = 0x0A
    SECURITY_REQUEST = 0x0B
    PUBLIC_KEY = 0x0C
    DHKEY_CHECK = 0x0D
    KEYPRESS = 0x0E


# Total PDU length including the code octet (Vol 3 Part H 3.5 / 3.6).
PDU_LEN = {1: 7, 2: 7, 3: 17, 4: 17, 5: 2, 6: 17, 7: 11, 8: 17, 9: 8, 10: 17, 11: 2,
           12: 65, 13: 17, 14: 2}
CODE_NAMES = {v: k for k, v in vars(CODE).items() if not k.startswith("_")}


class REASON:
    PASSKEY_ENTRY_FAILED = 0x01
    OOB_NOT_AVAILABLE = 0x02
    AUTH_REQUIREMENTS = 0x03
    CONFIRM_VALUE_FAILED = 0x04
    PAIRING_NOT_SUPPORTED = 0x05
    ENCRYPTION_KEY_SIZE = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    UNSPECIFIED = 0x08
    REPEATED_ATTEMPTS = 0x09
    INVALID_PARAMETERS = 0x0A
    DHKEY_CHECK_FAILED = 0x0B
    NUMERIC_COMPARISON_FAILED = 0x0C
    BREDR_PAIRING_IN_PROGRESS = 0x0D
    CTKD_NOT_ALLOWED = 0x0E
    KEY_REJECTED = 0x0F


REASON_NAMES = {v: k for k, v in vars(REASON).items() if not k.startswith("_")}


class IO:
    DISPLAY_ONLY = 0
    DISPLAY_YES_NO = 1
    KEYBOARD_ONLY = 2
    NO_INPUT_NO_OUTPUT = 3
    KEYBOARD_DISPLAY = 4


AUTH_BONDING = 0x01
AUTH_MITM = 0x04
AUTH_SC = 0x08
AUTH_KEYPRESS = 0x10
AUTH_CT2 = 0x20

KD_ENC = 0x01
KD_ID = 0x02
KD_SIGN = 0x04
KD_LINK = 0x08
KD_VALID = 0x0F

JUST_WORKS, NUMERIC_COMPARISON, PASSKEY = "just_works", "numeric_comparison", "passkey"
# passkey roles: who types the passkey
PK_INIT_INPUTS, PK_RESP_INPUTS, PK_BOTH_INPUT = "initiator_inputs", "responder_inputs", "both_input"

_JW, _NC = (JUST_WORKS, None), (NUMERIC_COMPARISON, None)
_RD = (PASSKEY, PK_INIT_INPUTS)   # responder displays, initiator inputs
_ID = (PASSKEY, PK_RESP_INPUTS)   # initiator displays, responder inputs
_BI = (PASSKEY, PK_BOTH_INPUT)
# Vol 3 Part H Table 2.8: [responder_io][initiator_io] -> (legacy, secure connections)
_METHOD_TABLE = [
    [(_JW, _JW), (_JW, _JW), (_RD, _RD), (_JW, _JW), (_RD, _RD)],   # resp DisplayOnly
    [(_JW, _JW), (_JW, _NC), (_RD, _RD), (_JW, _JW), (_RD, _NC)],   # resp DisplayYesNo
    [(_ID, _ID), (_ID, _ID), (_BI, _BI), (_JW, _JW), (_ID, _ID)],   # resp KeyboardOnly
    [(_JW, _JW)] * 5,                                               # resp NoInputNoOutput
    [(_ID, _ID), (_ID, _NC), (_RD, _RD), (_JW, _JW), (_ID, _NC)],   # resp KeyboardDisplay
]


def select_method(init_io: int, resp_io: int, sc: bool, mitm: bool) -> tuple[str, Optional[str]]:
    """Association model per 2.3.5.1 (OOB is handled by the caller)."""
    if not mitm:
        return _JW
    return _METHOD_TABLE[resp_io][init_io][1 if sc else 0]


TIMEOUT_S = 30.0


# ------------------------------------------------------------------ public data types
@dataclass
class SmpConfig:
    io_cap: int = IO.NO_INPUT_NO_OUTPUT
    bonding: bool = True
    mitm: bool = False
    sc: bool = True
    sc_only: bool = False          # refuse legacy pairing (Authentication Requirements)
    keypress: bool = False
    max_key_size: int = 16
    min_key_size: int = 7
    init_key_dist: int = KD_ENC | KD_ID | KD_SIGN   # keys we want the initiator to send
    resp_key_dist: int = KD_ENC | KD_ID | KD_SIGN   # keys we want the responder to send
    accept_pairing: bool = True    # as peripheral: answer Pairing Request at all
    sc_debug_keys: bool = False    # use the spec debug P-256 key pair (sniffer-decryptable)
    # Peer quirk (observed on one commercial peripheral): the confirm is computed as
    # f4(own_x, peer_x, rnd, z) instead of the
    # spec's f4(own_x, own_y, rnd, z). Enable with SMP_F4_XCROSS=1 for device runs.
    # Some peers ask for ENC keys (rkd bit) even in SC, where the spec derives the LTK.
    # Distribute the derived LTK in legacy format so the peer stops waiting. SMP_DIST_LTK=1
    dist_ltk_sc: bool = field(
        default_factory=lambda: os.environ.get("SMP_DIST_LTK") == "1")
    # Peer quirk (observed): it never starts key distribution, so the initiator sends
    # its keys first instead of waiting for the responder. SMP_KEYS_FIRST=1.
    keys_first: bool = field(
        default_factory=lambda: os.environ.get("SMP_KEYS_FIRST") == "1")
    # Peer quirk (observed): after our DHKey Check it stays silent instead of sending Eb.
    # Start encryption right away instead of waiting for it. SMP_EAGER_ENCRYPT=1.
    eager_encrypt: bool = field(
        default_factory=lambda: os.environ.get("SMP_EAGER_ENCRYPT") == "1")
    f4_xcross: bool = field(
        default_factory=lambda: os.environ.get("SMP_F4_XCROSS") == "1")
    timeout_s: float = TIMEOUT_S


class PairingDelegate:
    """User interaction hooks. Synchronous: they are called inside Hci.pump()."""

    def display_passkey(self, handle: int, passkey: int) -> None:
        log.info("handle 0x%03x: passkey %06d", handle, passkey)

    def request_passkey(self, handle: int) -> Optional[int]:
        return None   # None -> Passkey Entry Failed

    def confirm_numeric(self, handle: int, value: int) -> bool:
        log.info("handle 0x%03x: numeric comparison %06d (rejected by default delegate)", handle, value)
        return False

    def keypress(self, handle: int, kind: int) -> None:
        pass


@dataclass
class KeySet:
    ltk: Optional[bytes] = None
    ediv: Optional[int] = None
    rand: Optional[bytes] = None
    irk: Optional[bytes] = None
    identity_addr: Optional[bytes] = None    # 6 bytes LE
    identity_addr_type: Optional[int] = None
    csrk: Optional[bytes] = None


@dataclass
class Bond:
    peer: tuple[str, int]
    sc: bool
    authenticated: bool
    key_size: int
    ltk: Optional[bytes]          # SC: derived LTK (EDIV=0, Rand=0)
    local: KeySet = field(default_factory=KeySet)   # keys we distributed
    remote: KeySet = field(default_factory=KeySet)  # keys the peer distributed


@dataclass
class PairingResult:
    handle: int
    success: bool
    reason: Optional[int] = None   # SMP failure reason (sent or received)
    remote: bool = False           # True if the peer sent Pairing Failed
    timeout: bool = False
    detail: str = ""
    sc: bool = False
    method: Optional[str] = None
    key_size: int = 0
    authenticated: bool = False
    bonded: bool = False
    stk_or_ltk: Optional[bytes] = None
    local_keys: KeySet = field(default_factory=KeySet)
    remote_keys: KeySet = field(default_factory=KeySet)

    def __str__(self) -> str:
        if self.success:
            return (f"pairing OK handle=0x{self.handle:03x} sc={self.sc} method={self.method} "
                    f"key_size={self.key_size} authenticated={self.authenticated} bonded={self.bonded}")
        who = "remote" if self.remote else ("timeout" if self.timeout else "local")
        rn = REASON_NAMES.get(self.reason, "-") if self.reason is not None else "-"
        return f"pairing FAILED handle=0x{self.handle:03x} ({who}) reason={self.reason} {rn} {self.detail}"


class SmpFail(Exception):
    def __init__(self, reason: int, detail: str = ""):
        self.reason, self.detail = reason, detail
        super().__init__(f"{REASON_NAMES.get(reason, reason)}: {detail}")


# ------------------------------------------------------------------ PDU helpers
def build_pairing(code: int, io: int, oob: int, auth: int, max_key: int, ikd: int, rkd: int) -> bytes:
    return struct.pack("<7B", code, io, oob, auth, max_key, ikd, rkd)


@dataclass
class PairingParams:
    io: int
    oob: int
    auth: int
    max_key: int
    ikd: int
    rkd: int

    @classmethod
    def parse(cls, pdu: bytes) -> "PairingParams":
        io, oob, auth, mk, ikd, rkd = pdu[1:7]
        if io > IO.KEYBOARD_DISPLAY:
            raise SmpFail(REASON.INVALID_PARAMETERS, f"IO capability 0x{io:02x}")
        if oob > 1:
            raise SmpFail(REASON.INVALID_PARAMETERS, f"OOB flag 0x{oob:02x}")
        if mk > 16:
            raise SmpFail(REASON.INVALID_PARAMETERS, f"max key size {mk}")
        if mk < 7:
            raise SmpFail(REASON.ENCRYPTION_KEY_SIZE, f"max key size {mk}")
        # RFU bits in AuthReq / key distribution are ignored on receipt (3.5.1)
        return cls(io, oob, auth, mk, ikd & KD_VALID, rkd & KD_VALID)


class _S:  # session states
    IDLE = "idle"
    WAIT_RSP = "wait_pairing_response"
    WAIT_REQ = "wait_pairing_request"       # peripheral after sending Security Request
    WAIT_PUBKEY = "wait_public_key"
    WAIT_CONFIRM = "wait_confirm"
    WAIT_RANDOM = "wait_random"
    WAIT_DHKEY = "wait_dhkey_check"
    WAIT_ENCRYPT = "wait_encryption"
    KEY_DIST = "key_distribution"
    DONE = "done"
    FAILED = "failed"
    TIMEOUT = "timeout"


_ACTIVE = {_S.WAIT_RSP, _S.WAIT_PUBKEY, _S.WAIT_CONFIRM, _S.WAIT_RANDOM, _S.WAIT_DHKEY,
           _S.WAIT_ENCRYPT, _S.KEY_DIST}


class _Session:
    def __init__(self, handle: int, initiator: bool):
        self.handle, self.initiator = handle, initiator
        self.state = _S.IDLE
        self.expect: set[int] = set()
        self.deadline: Optional[float] = None
        self.preq = self.pres = b""
        self.sc = False
        self.method: Optional[str] = None
        self.pk_role: Optional[str] = None
        self.authenticated = False
        self.keypress = False
        self.key_size = 0
        self.ikd = self.rkd = 0
        self.tk = bytes(16)
        self.passkey: Optional[int] = None
        self.lrand = self.rrand = self.rconfirm = b""
        self.priv = self.pub = self.peer_pub = self.dhk = b""
        self.mackey = self.ltk = b""
        self.na = self.nb = b""
        self.round = 0
        self.a = self.b = b""          # SC A/B (7 bytes) = initiator / responder
        self.ia = self.ra = b""        # legacy 6-byte addresses
        self.iat = self.rat = 0
        self.peer: tuple[str, int] = ("", 0)
        self.bonding = False
        self.local_keys = KeySet()
        self.remote_keys = KeySet()
        self.remote_pending: list[int] = []
        self.local_sent = False
        self.r_check = bytes(16)       # SC f6 'r' (passkey or 0)
        self.early_kd: list[bytes] = []  # key-dist PDUs that beat the Encryption Change event


def _f4_confirm(cfg, own_pub: bytes, peer_pub: bytes, rnd: bytes, z: int) -> bytes:
    """Confirm value for SC.

    Spec: f4(PK_own_x, PK_own_y, rnd, z). Some peers instead mix the X coordinates of
    both keys -- f4(PK_own_x, PK_peer_x, rnd, z) -- which is reproduced by
    `f4_xcross` (two independent captures agree byte-for-byte).
    """
    if cfg is not None and getattr(cfg, "f4_xcross", False):
        return C.f4(bytes(own_pub)[:32], bytes(peer_pub)[:32], rnd, z)
    return C.f4(*_coords(own_pub), rnd, z)


def _coords(pub: bytes) -> tuple[bytes, bytes]:
    """Return (x, y) as used in f4; SMP_PUB_ORDER=yx swaps them for experiments."""
    import os
    if os.environ.get("SMP_PUB_ORDER", "xy").lower() == "yx":
        return pub[32:], pub[:32]
    return pub[:32], pub[32:]


class Smp:
    """SMP manager for all links of one Hci/L2cap instance."""

    def __init__(self, hci, l2cap, config: Optional[SmpConfig] = None,
                 delegate: Optional[PairingDelegate] = None, *,
                 rng: Callable[[int], bytes] = os.urandom, clock: Callable[[], float] = time.monotonic):
        self.hci, self.l2 = hci, l2cap
        self.cfg = config or SmpConfig()
        log.info("SMP public-key order: %s", __import__("os").environ.get("SMP_PUB_ORDER", "xy"))
        self.delegate = delegate or PairingDelegate()
        self.rng, self.clock = rng, clock
        self.sessions: dict[int, _Session] = {}
        self.results: dict[int, PairingResult] = {}
        self.history: list[PairingResult] = []
        self.bonds: dict[tuple[str, int], Bond] = {}
        self.on_complete: list[Callable[[PairingResult], None]] = []
        self.encrypted: set[int] = set()
        self.errors = 0          # exceptions caught inside handlers (should stay 0)
        self._deferred: list[Callable[[], None]] = []
        self._pending_enc: dict[int, Optional[_Session]] = {}
        l2cap.cid_handlers[CID_SMP] = self._on_pdu
        l2cap.cid_handlers[CID_BREDR_SMP] = self._on_bredr_pdu
        hci.handlers.append(self._on_event)
        hci.tick_handlers.append(self.tick)

    # ============================================================== public API
    def pair(self, handle: int) -> None:
        """Central: send Pairing Request. Peripheral: send Security Request."""
        conn = self.hci.le_conns.get(handle)
        if conn is None:
            raise ValueError(f"handle 0x{handle:03x} is not an LE connection")
        if conn["role"] == 0:
            s = self._new_session(handle, initiator=True)
            s.preq = build_pairing(CODE.PAIRING_REQUEST, self.cfg.io_cap, 0, self._local_auth(),
                                   self.cfg.max_key_size, self.cfg.init_key_dist & 0x07,
                                   self.cfg.resp_key_dist & 0x07)
            s.state, s.expect = _S.WAIT_RSP, {CODE.PAIRING_RESPONSE}
            self._send(s, s.preq)
        else:
            s = self._new_session(handle, initiator=False)
            s.state, s.expect = _S.WAIT_REQ, {CODE.PAIRING_REQUEST}
            self._send(s, bytes([CODE.SECURITY_REQUEST, self._local_auth()]))

    def encrypt(self, handle: int) -> None:
        """Central: start encryption with a stored bond (no pairing)."""
        conn = self.hci.le_conns[handle]
        bond = self.bonds.get((conn["peer_addr"], conn["peer_addr_type"]))
        if bond is None:
            raise KeyError("no bond for this peer")
        if bond.sc:
            ltk, ediv, rand = bond.ltk, 0, bytes(8)
        else:
            ltk, ediv, rand = bond.remote.ltk, bond.remote.ediv, bond.remote.rand
            if ltk is None:
                raise KeyError("peer did not distribute an LTK")
        self._pending_enc[handle] = None
        self._defer(lambda: self._start_encryption(handle, ltk, ediv, rand, None))

    def state(self, handle: int) -> str:
        s = self.sessions.get(handle)
        return s.state if s else _S.IDLE

    def _check_timeouts(self) -> None:
        now = self.clock()
        for s in list(self.sessions.values()):
            if s.state in _ACTIVE | {_S.WAIT_REQ} and s.deadline is not None and now > s.deadline:
                # 3.4: on timeout no Pairing Failed is sent and SMP stays silent on this link
                log.warning("handle 0x%03x: SMP timeout in state %s", s.handle, s.state)
                s.state, s.expect = _S.TIMEOUT, set()
                self._pending_enc.pop(s.handle, None)
                self._finish(s, PairingResult(s.handle, False, timeout=True,
                                              detail=f"SMP timeout ({self.cfg.timeout_s:.0f}s)"))

    def tick(self) -> None:
        """Called at the end of every Hci.pump(): timer check + deferred HCI commands."""
        self._check_timeouts()
        work, self._deferred = self._deferred, []
        for fn in work:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 -- never propagate into pump()
                self.errors += 1
                log.exception("deferred SMP action failed: %s", exc)

    # ============================================================== internals
    def _local_auth(self) -> int:
        a = AUTH_BONDING if self.cfg.bonding else 0
        if self.cfg.mitm:
            a |= AUTH_MITM
        if self.cfg.sc:
            a |= AUTH_SC
        if self.cfg.keypress:
            a |= AUTH_KEYPRESS
        return a

    def _new_session(self, handle: int, initiator: bool) -> _Session:
        s = _Session(handle, initiator)
        self.sessions[handle] = s
        self.results.pop(handle, None)
        s.deadline = self.clock() + self.cfg.timeout_s
        return s

    def _defer(self, fn: Callable[[], None]) -> None:
        self._deferred.append(fn)

    def _send(self, s: Optional[_Session], pdu: bytes, handle: Optional[int] = None) -> None:
        h = s.handle if s else handle
        log.debug("smp > 0x%03x %s %s", h, CODE_NAMES.get(pdu[0], pdu[0]), pdu.hex())
        import os as _os
        if _os.environ.get("SMP_DUMP") in ("1", "tx"):
            log.info("smp pdu tx hex=%s", pdu.hex())
        if s is not None:
            s.deadline = self.clock() + self.cfg.timeout_s  # reset when a command is queued
        self.l2.send(h, CID_SMP, pdu)

    def _rand(self, n: int) -> bytes:
        return bytes(self.rng(n))

    def _finish(self, s: _Session, r: PairingResult) -> None:
        r.sc, r.method, r.key_size = s.sc, s.method, s.key_size
        r.local_keys, r.remote_keys = s.local_keys, s.remote_keys
        if r.success:
            r.authenticated = s.authenticated
            r.stk_or_ltk = s.ltk
            if s.bonding:
                bond = Bond(s.peer, s.sc, s.authenticated, s.key_size, s.ltk if s.sc else None,
                            s.local_keys, s.remote_keys)
                self.bonds[s.peer] = bond
                r.bonded = True
        self.results[s.handle] = r
        self.history.append(r)
        log.info("%s", r)
        for cb in list(self.on_complete):
            cb(r)

    def _fail(self, s: _Session, reason: int, detail: str = "", send: bool = True) -> None:
        if send:
            try:
                self.l2.send(s.handle, CID_SMP, bytes([CODE.PAIRING_FAILED, reason]))
            except Exception as exc:  # noqa: BLE001
                log.warning("could not send Pairing Failed: %s", exc)
        s.state, s.expect, s.deadline = _S.FAILED, set(), None
        self._finish(s, PairingResult(s.handle, False, reason=reason, detail=detail))

    # ------------------------------------------------------------- PDU entry point
    def _on_pdu(self, handle: int, pdu: bytes) -> None:
        if pdu:
            s0 = self.sessions.get(handle)
            import os as _os
            if _os.environ.get("SMP_DUMP"):
                log.info("smp pdu hex=%s", pdu.hex())
            log.info("smp rx handle=0x%03x code=0x%02x len=%d expect=%s state=%s",
                     handle, pdu[0], len(pdu),
                     sorted(s0.expect) if s0 else None, s0.state if s0 else None)
        try:
            self._handle_pdu(handle, bytes(pdu))
        except Exception as exc:  # noqa: BLE001 -- a PDU must never crash the stack
            self.errors += 1
            log.exception("SMP handler error on %s", pdu.hex())
            s = self.sessions.get(handle)
            try:
                if s is not None and s.state in _ACTIVE | {_S.WAIT_REQ}:
                    self._fail(s, REASON.UNSPECIFIED, f"internal error: {exc}")
                elif s is None or s.state != _S.TIMEOUT:
                    self.l2.send(handle, CID_SMP, bytes([CODE.PAIRING_FAILED, REASON.UNSPECIFIED]))
            except Exception:  # noqa: BLE001
                log.exception("could not report SMP internal error")

    def _handle_pdu(self, handle: int, pdu: bytes) -> None:
        log.debug("smp < 0x%03x %s", handle, pdu.hex())
        s = self.sessions.get(handle)
        if s is not None and s.state == _S.TIMEOUT:
            log.info("handle 0x%03x: SMP PDU after timeout ignored", handle)
            return
        if s is not None and s.state in _ACTIVE | {_S.WAIT_REQ} and s.deadline is not None \
                and self.clock() > s.deadline:
            self._check_timeouts()
            return
        conn = self.hci.le_conns.get(handle)
        if conn is None:
            log.warning("SMP on non-LE handle 0x%03x ignored", handle)
            return
        if not pdu:
            return self._reject(s, handle, REASON.INVALID_PARAMETERS, "empty PDU")
        code = pdu[0]
        if code not in PDU_LEN:
            return self._reject(s, handle, REASON.COMMAND_NOT_SUPPORTED, f"code 0x{code:02x}")
        if code == CODE.PAIRING_FAILED:
            if s is None or s.state not in _ACTIVE | {_S.WAIT_REQ}:
                log.info("handle 0x%03x: Pairing Failed outside pairing ignored", handle)
                return
            reason = pdu[1] if len(pdu) == 2 else None
            s.state, s.expect, s.deadline = _S.FAILED, set(), None
            self._finish(s, PairingResult(handle, False, reason=reason, remote=True,
                                          detail="" if reason is not None else f"malformed {pdu.hex()}"))
            return
        if len(pdu) != PDU_LEN[code]:
            return self._reject(s, handle, REASON.INVALID_PARAMETERS,
                                f"{CODE_NAMES[code]} length {len(pdu)} != {PDU_LEN[code]}")
        central = conn["role"] == 0
        if code == CODE.PAIRING_REQUEST:
            # The peripheral may be the SMP initiator (observed in testing): answer as
            # responder regardless of our GAP role, replacing any half-open session.
            if s is not None and s.state in _ACTIVE:
                log.info("peer-initiated Pairing Request overrides our session")
                s.state, s.expect = _S.FAILED, set()
            return self._guard(self._new_session(handle, False), self._rx_pairing_request, pdu)
        if code == CODE.SECURITY_REQUEST:
            if not central:
                return self._reject(s, handle, REASON.COMMAND_NOT_SUPPORTED, "Security Request to peripheral")
            if s is not None and s.state in _ACTIVE:
                log.info("Security Request during pairing ignored")
                return
            return self._rx_security_request(handle, pdu)
        if s is not None and s.state == _S.WAIT_ENCRYPT and CODE.ENCRYPTION_INFO <= code <= CODE.SIGNING_INFO \
                and len(s.early_kd) < 6:
            # USB delivers events and ACL on different endpoints: the peer's first key PDU can
            # be read before our Encryption Change. Hold it and replay it once encrypted.
            s.early_kd.append(pdu)
            return
        if s is None or code not in s.expect:
            st = s.state if s else _S.IDLE
            return self._reject(s, handle, REASON.UNSPECIFIED, f"unexpected {CODE_NAMES[code]} in {st}")
        handler = {
            CODE.PAIRING_RESPONSE: self._rx_pairing_response,
            CODE.PAIRING_CONFIRM: self._rx_confirm,
            CODE.PAIRING_RANDOM: self._rx_random,
            CODE.PUBLIC_KEY: self._rx_public_key,
            CODE.DHKEY_CHECK: self._rx_dhkey_check,
            CODE.KEYPRESS: self._rx_keypress,
        }.get(code, self._rx_key_dist)
        self._guard(s, handler, pdu)

    def _guard(self, s: _Session, fn, pdu: bytes) -> None:
        try:
            fn(s, pdu)
        except SmpFail as f:
            self._fail(s, f.reason, f.detail)
        except C.InvalidPublicKey as exc:
            self._fail(s, REASON.DHKEY_CHECK_FAILED, f"invalid public key: {exc}")

    def _reject(self, s: Optional[_Session], handle: int, reason: int, detail: str) -> None:
        """Malformed / out-of-order PDU: always answer Pairing Failed and abort any pairing."""
        log.warning("handle 0x%03x: %s -> Pairing Failed 0x%02x", handle, detail, reason)
        if s is not None and s.state in _ACTIVE | {_S.WAIT_REQ}:
            self._fail(s, reason, detail)
        else:
            self.l2.send(handle, CID_SMP, bytes([CODE.PAIRING_FAILED, reason]))

    def _on_bredr_pdu(self, handle: int, pdu: bytes) -> None:
        # BR/EDR SMP is only for cross-transport key derivation, which we do not implement.
        if pdu and pdu[0] == CODE.PAIRING_FAILED:
            return
        log.info("BR/EDR SMP PDU %s on 0x%03x refused", pdu.hex(), handle)
        try:
            self.l2.send(handle, CID_BREDR_SMP, bytes([CODE.PAIRING_FAILED, REASON.PAIRING_NOT_SUPPORTED]))
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            log.warning("BR/EDR SMP reply failed: %s", exc)

    # ------------------------------------------------------------- feature exchange
    def _addresses(self, s: _Session) -> None:
        conn = self.hci.le_conns[s.handle]
        if not self.hci.bd_addr:
            raise SmpFail(REASON.UNSPECIFIED, "local BD_ADDR unknown (call read_bd_addr)")
        local, ltype = bdaddr_bytes(self.hci.bd_addr), 0  # ASSUMPTION: public own address
        peer, ptype = bdaddr_bytes(conn["peer_addr"]), conn["peer_addr_type"] & 1
        s.peer = (conn["peer_addr"], conn["peer_addr_type"])
        if s.initiator:
            s.ia, s.iat, s.ra, s.rat = local, ltype, peer, ptype
        else:
            s.ia, s.iat, s.ra, s.rat = peer, ptype, local, ltype
        s.a, s.b = s.ia + bytes([s.iat]), s.ra + bytes([s.rat])

    def _negotiate(self, s: _Session, req: PairingParams, rsp: PairingParams) -> None:
        s.sc = bool(req.auth & AUTH_SC and rsp.auth & AUTH_SC)
        if self.cfg.sc_only and not s.sc:
            raise SmpFail(REASON.AUTH_REQUIREMENTS, "Secure Connections only")
        s.key_size = min(req.max_key, rsp.max_key)
        if s.key_size < max(7, self.cfg.min_key_size):
            raise SmpFail(REASON.ENCRYPTION_KEY_SIZE, f"key size {s.key_size}")
        oob = (req.oob and rsp.oob) if not s.sc else (req.oob or rsp.oob)
        if oob:
            raise SmpFail(REASON.OOB_NOT_AVAILABLE, "OOB pairing not implemented")
        mitm = bool((req.auth | rsp.auth) & AUTH_MITM)
        s.method, s.pk_role = select_method(req.io, rsp.io, s.sc, mitm)
        s.authenticated = s.method != JUST_WORKS
        if self.cfg.mitm and not s.authenticated:
            raise SmpFail(REASON.AUTH_REQUIREMENTS, "MITM required but only Just Works possible")
        s.keypress = bool(req.auth & rsp.auth & AUTH_KEYPRESS) and s.method == PASSKEY
        s.bonding = bool(req.auth & rsp.auth & AUTH_BONDING)
        s.ikd, s.rkd = req.ikd & rsp.ikd, req.rkd & rsp.rkd
        if s.sc:  # LTK is derived; EncKey ignored. No CTKD -> no LinkKey.
            s.ikd &= ~(KD_ENC | KD_LINK)
            s.rkd &= ~(KD_ENC | KD_LINK)
        else:
            s.ikd &= ~KD_LINK
            s.rkd &= ~KD_LINK
        if not s.bonding:
            s.ikd = s.rkd = 0
        if s.method == PASSKEY and not self._local_inputs(s):
            self._get_passkey(s)   # displaying side: show it before anything goes on air
        log.info("handle 0x%03x: %s %s%s key_size=%d ikd=%x rkd=%x", s.handle,
                 "SC" if s.sc else "legacy", s.method, f"/{s.pk_role}" if s.pk_role else "",
                 s.key_size, s.ikd, s.rkd)

    def _rx_pairing_request(self, s: _Session, pdu: bytes) -> None:
        s.preq = pdu
        req = PairingParams.parse(pdu)
        if not self.cfg.accept_pairing:
            raise SmpFail(REASON.PAIRING_NOT_SUPPORTED, "pairing disabled")
        self._addresses(s)
        auth = self._local_auth()
        oob = 0
        ikd = req.ikd & self.cfg.init_key_dist & 0x07
        rkd = req.rkd & self.cfg.resp_key_dist & 0x07
        s.pres = build_pairing(CODE.PAIRING_RESPONSE, self.cfg.io_cap, oob, auth,
                               self.cfg.max_key_size, ikd, rkd)
        self._negotiate(s, req, PairingParams.parse(s.pres))
        self._send(s, s.pres)
        if s.sc:
            s.state, s.expect = _S.WAIT_PUBKEY, {CODE.PUBLIC_KEY}
        else:
            self._legacy_tk(s)
            s.state, s.expect = _S.WAIT_CONFIRM, {CODE.PAIRING_CONFIRM} | self._kp(s)

    def _rx_pairing_response(self, s: _Session, pdu: bytes) -> None:
        s.pres = pdu
        rsp = PairingParams.parse(pdu)
        req = PairingParams.parse(s.preq)
        if rsp.ikd & ~req.ikd or rsp.rkd & ~req.rkd:
            raise SmpFail(REASON.INVALID_PARAMETERS, "responder set key distribution bits we did not request")
        self._addresses(s)
        self._negotiate(s, req, rsp)
        if s.sc:
            self._send_public_key(s)
            s.state, s.expect = _S.WAIT_PUBKEY, {CODE.PUBLIC_KEY}
        else:
            self._legacy_tk(s)
            s.lrand = self._rand(16)
            self._send(s, bytes([CODE.PAIRING_CONFIRM]) + self._c1(s, s.lrand))
            s.state, s.expect = _S.WAIT_CONFIRM, {CODE.PAIRING_CONFIRM}

    def _rx_security_request(self, handle: int, pdu: bytes) -> None:
        conn = self.hci.le_conns[handle]
        bond = self.bonds.get((conn["peer_addr"], conn["peer_addr_type"]))
        auth = pdu[1]
        if bond is not None and (bond.authenticated or not auth & AUTH_MITM) and \
                (bond.sc or not auth & AUTH_SC):
            log.info("Security Request: encrypting with stored bond")
            self.encrypt(handle)
        else:
            self.pair(handle)

    def _kp(self, s: _Session) -> set[int]:
        return {CODE.KEYPRESS} if s.keypress else set()

    def _rx_keypress(self, s: _Session, pdu: bytes) -> None:
        if pdu[1] > 4:
            raise SmpFail(REASON.INVALID_PARAMETERS, f"keypress type {pdu[1]}")
        self.delegate.keypress(s.handle, pdu[1])

    # ------------------------------------------------------------- passkey / TK
    def _local_inputs(self, s: _Session) -> bool:
        return s.pk_role == PK_BOTH_INPUT or (s.pk_role == PK_INIT_INPUTS) == s.initiator

    def _get_passkey(self, s: _Session) -> int:
        if s.passkey is not None:
            return s.passkey
        if self._local_inputs(s):
            pk = self.delegate.request_passkey(s.handle)
            if pk is None or not 0 <= int(pk) <= 999999:
                raise SmpFail(REASON.PASSKEY_ENTRY_FAILED, "passkey entry cancelled/invalid")
            s.passkey = int(pk)
        else:
            s.passkey = int.from_bytes(self._rand(4), "little") % 1_000_000
            self.delegate.display_passkey(s.handle, s.passkey)
        return s.passkey

    def _legacy_tk(self, s: _Session) -> None:
        s.tk = self._get_passkey(s).to_bytes(16, "little") if s.method == PASSKEY else bytes(16)

    # ------------------------------------------------------------- legacy
    def _c1(self, s: _Session, r: bytes) -> bytes:
        return C.c1(s.tk, r, s.preq, s.pres, s.iat, s.ia, s.rat, s.ra)

    def _rx_confirm(self, s: _Session, pdu: bytes) -> None:
        log.info("smp rx confirm initiator=%s state=%s", s.initiator, s.state)
        s.rconfirm = pdu[1:]
        if not s.sc:
            if s.initiator:   # got Sconfirm -> send Mrand
                self._send(s, bytes([CODE.PAIRING_RANDOM]) + s.lrand)
            else:             # got Mconfirm -> send Sconfirm
                s.lrand = self._rand(16)
                self._send(s, bytes([CODE.PAIRING_CONFIRM]) + self._c1(s, s.lrand))
            s.state, s.expect = _S.WAIT_RANDOM, {CODE.PAIRING_RANDOM}
            return
        if s.method == PASSKEY:
            if s.initiator:   # Cbi received -> send Nai
                self._send(s, bytes([CODE.PAIRING_RANDOM]) + s.na)
            else:             # Cai received -> send Cbi
                s.nb = self._rand(16)
                self._send(s, bytes([CODE.PAIRING_CONFIRM]) +
                           _f4_confirm(self.cfg, s.pub, s.peer_pub, s.nb, self._rbit(s)))
        else:                 # JW/NC: initiator got Cb -> send Na
            # Na must be the one bound into Ca; never regenerate it here.
            if not s.na:
                s.na = self._rand(16)
            self._send(s, bytes([CODE.PAIRING_RANDOM]) + s.na)
        s.state, s.expect = _S.WAIT_RANDOM, {CODE.PAIRING_RANDOM}

    def _rx_random(self, s: _Session, pdu: bytes) -> None:
        log.info("smp rx random initiator=%s rconfirm=%s", s.initiator, s.rconfirm is not None)
        if not s.sc:
            return self._legacy_random(s, pdu[1:])
        if s.method == PASSKEY:
            return self._sc_passkey_random(s, pdu[1:])
        pka, pkb = (s.pub, s.peer_pub) if s.initiator else (s.peer_pub, s.pub)
        if s.initiator:
            if s.rconfirm is None:
                # Nb before Cb is a protocol violation; do not send Na.
                raise SmpFail(REASON.UNSPECIFIED, "Pairing Random before Confirm")
            s.nb = pdu[1:]
            if _f4_confirm(self.cfg, pkb, pka, s.nb, 0) != s.rconfirm:
                raise SmpFail(REASON.CONFIRM_VALUE_FAILED, "Cb mismatch")
        else:
            s.na = pdu[1:]
            self._send(s, bytes([CODE.PAIRING_RANDOM]) + s.nb)
        if s.method == NUMERIC_COMPARISON:
            v = C.g2(pka[:32], pkb[:32], s.na, s.nb)
            if not self.delegate.confirm_numeric(s.handle, v):
                raise SmpFail(REASON.NUMERIC_COMPARISON_FAILED, f"user rejected {v:06d}")
        self._sc_phase2(s)

    def _legacy_random(self, s: _Session, r: bytes) -> None:
        s.rrand = r
        if self._c1(s, r) != s.rconfirm:
            raise SmpFail(REASON.CONFIRM_VALUE_FAILED,
                          ("Sconfirm" if s.initiator else "Mconfirm") + " mismatch")
        mrand, srand = (s.lrand, r) if s.initiator else (r, s.lrand)
        s.ltk = C.mask_key(C.s1(s.tk, srand, mrand), s.key_size)  # STK
        if s.initiator:
            self._await_encryption(s)
            self._defer(lambda: self._start_encryption(s.handle, s.ltk, 0, bytes(8), s))
        else:
            self._send(s, bytes([CODE.PAIRING_RANDOM]) + s.lrand)
            self._await_encryption(s)

    # ------------------------------------------------------------- secure connections
    def _send_public_key(self, s: _Session) -> None:
        if self.cfg.sc_debug_keys:
            s.priv, s.pub = C.DEBUG_PRIVATE_KEY, C.DEBUG_PUBLIC_KEY
        else:
            s.priv, s.pub = C.generate_keypair(self._rand)
        self._send(s, bytes([CODE.PUBLIC_KEY]) + s.pub)

    def _rx_public_key(self, s: _Session, pdu: bytes) -> None:
        peer = pdu[1:]
        C.validate_public_key(peer)           # -> DHKey Check Failed via _guard
        if not s.initiator:
            self._send_public_key(s)
        if peer == s.pub and not self.cfg.sc_debug_keys:
            raise SmpFail(REASON.DHKEY_CHECK_FAILED, "peer reflected our public key")
        s.peer_pub = peer
        s.dhk = C.dhkey(s.priv, peer)
        if s.method == PASSKEY:
            self._get_passkey(s)
            s.round = 0
            if s.initiator:
                self._sc_send_cai(s)
            s.state, s.expect = _S.WAIT_CONFIRM, {CODE.PAIRING_CONFIRM} | self._kp(s)
        elif s.initiator:   # JW/NC: send Ca = f4(PKax, PKay, Na, 0) before waiting for Cb
            self._sc_send_cai(s)
            s.state, s.expect = _S.WAIT_CONFIRM, {CODE.PAIRING_CONFIRM}
        else:   # responder JW/NC: send Cb = f4(PKbx, PKax, Nb, 0)
            s.nb = self._rand(16)
            self._send(s, bytes([CODE.PAIRING_CONFIRM]) +
                       _f4_confirm(self.cfg, s.pub, s.peer_pub, s.nb, 0))
            s.state, s.expect = _S.WAIT_RANDOM, {CODE.PAIRING_RANDOM}

    def _rbit(self, s: _Session) -> int:
        # Z: Just Works / Numeric Comparison use 0; Passkey uses 0x80 | bit.
        if s.method != PASSKEY:
            return 0
        return 0x80 | ((s.passkey >> s.round) & 1)

    def _sc_send_cai(self, s: _Session) -> None:
        s.na = self._rand(16)
        self._send(s, bytes([CODE.PAIRING_CONFIRM]) +
                   _f4_confirm(self.cfg, s.pub, s.peer_pub, s.na, self._rbit(s)))

    def _sc_passkey_random(self, s: _Session, n: bytes) -> None:
        if s.initiator:   # verify Cbi = f4(PKbx, PKax, Nbi, rbi)
            s.nb = n
            if _f4_confirm(self.cfg, s.peer_pub, s.pub, n, self._rbit(s)) != s.rconfirm:
                raise SmpFail(REASON.CONFIRM_VALUE_FAILED, f"passkey round {s.round}: Cb mismatch")
        else:             # verify Cai = f4(PKax, PKbx, Nai, rai), send Nbi
            s.na = n
            if _f4_confirm(self.cfg, s.peer_pub, s.pub, n, self._rbit(s)) != s.rconfirm:
                raise SmpFail(REASON.CONFIRM_VALUE_FAILED, f"passkey round {s.round}: Ca mismatch")
            self._send(s, bytes([CODE.PAIRING_RANDOM]) + s.nb)
        s.round += 1
        if s.round < 20:
            if s.initiator:
                self._sc_send_cai(s)
            s.state, s.expect = _S.WAIT_CONFIRM, {CODE.PAIRING_CONFIRM} | self._kp(s)
        else:
            self._sc_phase2(s)

    def _iocap(self, pdu: bytes) -> bytes:
        return pdu[1:4]   # IO capability, OOB flag, AuthReq (PDU order == LE order)

    def _sc_phase2(self, s: _Session) -> None:
        log.info("sc_phase2 initiator=%s dhk=%s na=%s nb=%s",
                 s.initiator, s.dhk.hex(), s.na.hex(), s.nb.hex())
        s.mackey, ltk = C.f5(s.dhk, s.na, s.nb, s.a, s.b)
        s.ltk = C.mask_key(ltk, s.key_size)
        r = (s.passkey or 0).to_bytes(16, "little") if s.method == PASSKEY else bytes(16)
        s.r_check = r
        if s.initiator:
            ea = C.f6(s.mackey, s.na, s.nb, r, self._iocap(s.preq), s.a, s.b)
            log.info("smp Ea=%s (eager_encrypt=%s)", ea.hex(), self.cfg.eager_encrypt)
            self._send(s, bytes([CODE.DHKEY_CHECK]) + ea)
            if self.cfg.eager_encrypt:
                # start encryption without waiting for Eb, but still register the session
                # so key distribution runs once the link is encrypted
                self._await_encryption(s)
                s.expect = {CODE.DHKEY_CHECK}   # still accept a late Eb
                self._defer(lambda: self._start_encryption(s.handle, s.ltk, 0, bytes(8), s))
                return
        s.state, s.expect = _S.WAIT_DHKEY, {CODE.DHKEY_CHECK}

    def _rx_dhkey_check(self, s: _Session, pdu: bytes) -> None:
        r = s.r_check
        if s.initiator:
            already = s.state != _S.WAIT_DHKEY
            eb = C.f6(s.mackey, s.nb, s.na, r, self._iocap(s.pres), s.b, s.a)
            if pdu[1:] != eb:
                raise SmpFail(REASON.DHKEY_CHECK_FAILED, "Eb mismatch")
            log.info("smp Eb verified (late=%s)", already)
            if already:
                return
            self._await_encryption(s)
            self._defer(lambda: self._start_encryption(s.handle, s.ltk, 0, bytes(8), s))
        else:
            ea = C.f6(s.mackey, s.na, s.nb, r, self._iocap(s.preq), s.a, s.b)
            log.warning("dhkey(responder) na=%s nb=%s a=%s b=%s iocap=%s calc=%s got=%s",
                        s.na.hex(), s.nb.hex(), s.a.hex(), s.b.hex(),
                        self._iocap(s.preq).hex(), ea.hex(), pdu[1:].hex())
            if pdu[1:] != ea:
                raise SmpFail(REASON.DHKEY_CHECK_FAILED, "Ea mismatch")
            self._send(s, bytes([CODE.DHKEY_CHECK]) + C.f6(s.mackey, s.nb, s.na, r,
                                                            self._iocap(s.pres), s.b, s.a))
            self._await_encryption(s)

    # ------------------------------------------------------------- encryption
    def _await_encryption(self, s: _Session) -> None:
        s.state, s.expect = _S.WAIT_ENCRYPT, set()
        self._pending_enc[s.handle] = s

    def _start_encryption(self, handle: int, ltk: bytes, ediv: int, rand: bytes,
                          s: Optional[_Session]) -> None:
        if s is not None and s.state != _S.WAIT_ENCRYPT:
            return
        ev = self.hci.le_start_encryption(handle, ltk, ediv, rand)
        st = ev.fields.get("status")
        if st not in (None, 0):
            self._pending_enc.pop(handle, None)
            if s is not None:
                self._fail(s, REASON.UNSPECIFIED, f"LE_Start_Encryption status 0x{st:02x}", send=False)

    def _ltk_reply(self, handle: int, ltk: Optional[bytes]) -> None:
        if ltk is None:
            self.hci.le_ltk_neg_reply(handle)
        else:
            self.hci.le_ltk_reply(handle, ltk)

    def _on_event(self, ev: Event) -> None:
        try:
            self._handle_event(ev)
        except Exception:  # noqa: BLE001
            self.errors += 1
            log.exception("SMP event handler error")

    def _handle_event(self, ev: Event) -> None:
        f = ev.fields
        if ev.code == EVT.LE_META and f.get("subevent") == LE_SUB.LTK_REQUEST:
            h = f["handle"]
            s = self.sessions.get(h)
            ltk = None
            if s is not None and s.state == _S.WAIT_ENCRYPT and not s.initiator \
                    and f["ediv"] == 0 and f["rand"] == bytes(8):
                ltk = s.ltk
            else:
                conn = self.hci.le_conns.get(h)
                bond = self.bonds.get((conn["peer_addr"], conn["peer_addr_type"])) if conn else None
                if bond is not None:
                    if bond.sc and f["ediv"] == 0 and f["rand"] == bytes(8):
                        ltk = bond.ltk
                    elif not bond.sc and bond.local.ltk is not None and \
                            f["ediv"] == bond.local.ediv and f["rand"] == bond.local.rand:
                        ltk = bond.local.ltk
                self._pending_enc.setdefault(h, None)
            log.info("LTK request handle 0x%03x ediv=%04x -> %s", h, f["ediv"], "reply" if ltk else "negative")
            self._defer(lambda: self._ltk_reply(h, ltk))
        elif ev.code in (EVT.ENCRYPTION_CHANGE, EVT.ENCRYPTION_KEY_REFRESH_COMPLETE):
            h = f.get("handle")
            ok = f.get("status") == 0 and f.get("enabled", 1) != 0
            if ok:
                self.encrypted.add(h)
            else:
                self.encrypted.discard(h)
            s = self._pending_enc.pop(h, None)
            if s is not None and s.state == _S.WAIT_ENCRYPT:
                if ok:
                    self._start_key_dist(s)
                else:
                    self._fail(s, REASON.UNSPECIFIED, f"encryption failed status 0x{f.get('status', 0):02x}",
                               send=False)
        elif ev.code == EVT.DISCONNECTION_COMPLETE:
            h = f.get("handle")
            self.encrypted.discard(h)
            self._pending_enc.pop(h, None)
            s = self.sessions.pop(h, None)
            if s is not None and s.state in _ACTIVE:
                s.state = _S.FAILED
                self._finish(s, PairingResult(h, False, detail=f"disconnected reason 0x{f.get('reason', 0):02x}"))

    # ------------------------------------------------------------- key distribution
    @staticmethod
    def _expected_codes(kd: int, sc: bool, dist_ltk: bool = False) -> list[int]:
        out = []
        if kd & KD_ENC and (not sc or dist_ltk):
            out += [CODE.ENCRYPTION_INFO, CODE.CENTRAL_IDENT]
        if kd & KD_ID:
            out += [CODE.IDENTITY_INFO, CODE.IDENTITY_ADDR_INFO]
        if kd & KD_SIGN:
            out += [CODE.SIGNING_INFO]
        return out

    def _start_key_dist(self, s: _Session) -> None:
        s.state = _S.KEY_DIST
        s.remote_pending = self._expected_codes(s.rkd if s.initiator else s.ikd, s.sc,
                                                self.cfg.dist_ltk_sc)
        if not s.initiator or self.cfg.keys_first:
            self._send_local_keys(s)
        self._kd_progress(s)
        early, s.early_kd = s.early_kd, []
        for pdu in early:
            self._handle_pdu(s.handle, pdu)

    def _send_local_keys(self, s: _Session) -> None:
        kd = s.ikd if s.initiator else s.rkd
        k = s.local_keys
        if kd & KD_ENC and (not s.sc or self.cfg.dist_ltk_sc):
            if s.sc:
                # SC derives the LTK; hand it over anyway in legacy format
                k.ltk = s.ltk or C.mask_key(self._rand(16), s.key_size)
                k.ediv, k.rand = 0, bytes(8)
            else:
                k.ltk = C.mask_key(self._rand(16), s.key_size)
                k.ediv, k.rand = int.from_bytes(self._rand(2), "little"), self._rand(8)
            self._send(s, bytes([CODE.ENCRYPTION_INFO]) + k.ltk)
            self._send(s, bytes([CODE.CENTRAL_IDENT]) + struct.pack("<H", k.ediv) + k.rand)
        if kd & KD_ID:
            k.irk = self._rand(16)
            k.identity_addr, k.identity_addr_type = bdaddr_bytes(self.hci.bd_addr), 0
            self._send(s, bytes([CODE.IDENTITY_INFO]) + k.irk)
            self._send(s, bytes([CODE.IDENTITY_ADDR_INFO, 0]) + k.identity_addr)
        if kd & KD_SIGN:
            k.csrk = self._rand(16)
            self._send(s, bytes([CODE.SIGNING_INFO]) + k.csrk)
        s.local_sent = True

    def _kd_progress(self, s: _Session) -> None:
        if s.remote_pending:
            s.expect = {s.remote_pending[0]}
            return
        if s.initiator and not s.local_sent:
            self._send_local_keys(s)
        s.state, s.expect, s.deadline = _S.DONE, set(), None
        self._finish(s, PairingResult(s.handle, True))

    def _rx_key_dist(self, s: _Session, pdu: bytes) -> None:
        if s.handle not in self.encrypted:
            raise SmpFail(REASON.UNSPECIFIED, "key distribution on unencrypted link")
        code, k = pdu[0], s.remote_keys
        if code == CODE.ENCRYPTION_INFO:
            k.ltk = pdu[1:]
        elif code == CODE.CENTRAL_IDENT:
            k.ediv, k.rand = struct.unpack_from("<H", pdu, 1)[0], pdu[3:11]
        elif code == CODE.IDENTITY_INFO:
            k.irk = pdu[1:]
        elif code == CODE.IDENTITY_ADDR_INFO:
            if pdu[1] > 1:
                raise SmpFail(REASON.INVALID_PARAMETERS, f"identity address type {pdu[1]}")
            k.identity_addr_type, k.identity_addr = pdu[1], pdu[2:8]
        elif code == CODE.SIGNING_INFO:
            k.csrk = pdu[1:]
        s.remote_pending.pop(0)
        self._kd_progress(s)
