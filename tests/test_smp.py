"""End-to-end SMP over the fake HCI/ACL path (host stack <-> FakeController <-> FakeSmpPeer)."""
import itertools
import random
import struct

import pytest

from rtlhci.acl import CID_BREDR_SMP, CID_SMP, L2cap, L2capReassembler
from rtlhci.fake import FakeController, FakeSmpPeer, FakeTransport
from rtlhci.hci import EVT, OP, Hci
from rtlhci.smp import (AUTH_BONDING, AUTH_KEYPRESS, AUTH_MITM, AUTH_SC, CODE, IO, JUST_WORKS,
                        KD_ENC, KD_ID, KD_SIGN, NUMERIC_COMPARISON, PASSKEY, PDU_LEN, REASON,
                        Smp, SmpConfig, select_method)
from smp_harness import HANDLE, make, run, start

ROLES = pytest.mark.parametrize("host_central", [True, False], ids=["host-central", "host-peripheral"])
LEGACY_AUTH = AUTH_BONDING
SC_AUTH = AUTH_BONDING | AUTH_SC


def host_tx_smp(ctl):
    out = []
    r = L2capReassembler(lambda h, c, p: out.append((c, p)))
    for p in ctl.acl_in:
        r.feed(p)
    return [p for c, p in out if c == CID_SMP]


def assert_success(smp, peer, sc, method):
    r = smp.results[HANDLE]
    assert r.success, str(r)
    assert (r.sc, r.method) == (sc, method)
    assert peer.done and peer.encrypted and peer.host_failed is None and peer.sent_failed is None
    assert r.stk_or_ltk == peer.ltk and HANDLE in smp.encrypted
    assert smp.errors == 0
    return r


# ------------------------------------------------------------------ happy paths
@ROLES
def test_legacy_just_works(host_central):
    ctl, h, smp, peer, d, _ = make(host_central, SmpConfig(sc=False), peer_kw=dict(auth=LEGACY_AUTH))
    start(host_central, h, smp, peer)
    run(h, smp)
    r = assert_success(smp, peer, False, JUST_WORKS)
    assert not r.authenticated and r.bonded and r.key_size == 16
    # legacy: both sides distributed LTK+EDIV/Rand, IRK+addr, CSRK in spec order
    assert sorted(peer.keys_from_host) == [6, 7, 8, 9, 10]
    assert r.remote_keys.ltk is not None and r.remote_keys.irk is not None and r.remote_keys.csrk
    assert r.remote_keys.identity_addr_type == 1
    if host_central:
        assert r.remote_keys.ltk == peer.dist_ltk[0] and r.remote_keys.ediv == peer.dist_ltk[1]
    codes = [p[0] for p in host_tx_smp(ctl)]
    dist = [c for c in codes if 6 <= c <= 10]
    assert dist == [6, 7, 8, 9, 10]


@ROLES
def test_sc_just_works(host_central):
    ctl, h, smp, peer, d, _ = make(host_central)
    start(host_central, h, smp, peer)
    run(h, smp)
    r = assert_success(smp, peer, True, JUST_WORKS)
    assert not r.authenticated
    # SC: no Encryption Info / Central Identification on air (LTK is derived)
    assert sorted(peer.keys_from_host) == [8, 9, 10]
    assert not any(p[0] in (6, 7) for p in host_tx_smp(ctl))
    assert r.remote_keys.ltk is None


@ROLES
def test_sc_numeric_comparison(host_central):
    io = IO.DISPLAY_YES_NO
    ctl, h, smp, peer, d, _ = make(host_central, SmpConfig(io_cap=io, mitm=True),
                                   peer_kw=dict(io=IO.KEYBOARD_DISPLAY, auth=SC_AUTH | AUTH_MITM))
    start(host_central, h, smp, peer)
    run(h, smp)
    r = assert_success(smp, peer, True, NUMERIC_COMPARISON)
    assert r.authenticated and d.nc == [peer.nc_value]


@ROLES
@pytest.mark.parametrize("sc", [False, True], ids=["legacy", "sc"])
@pytest.mark.parametrize("host_io,peer_io", [(IO.KEYBOARD_ONLY, IO.DISPLAY_ONLY),
                                             (IO.DISPLAY_ONLY, IO.KEYBOARD_ONLY),
                                             (IO.KEYBOARD_ONLY, IO.KEYBOARD_ONLY)],
                         ids=["host-types", "host-displays", "both-type"])
def test_passkey(host_central, sc, host_io, peer_io):
    auth = (SC_AUTH if sc else LEGACY_AUTH) | AUTH_MITM
    ctl, h, smp, peer, d, _ = make(host_central, SmpConfig(io_cap=host_io, mitm=True, sc=sc),
                                   peer_kw=dict(io=peer_io, auth=auth))
    start(host_central, h, smp, peer)
    run(h, smp)
    r = assert_success(smp, peer, sc, PASSKEY)
    assert r.authenticated
    if host_io == IO.DISPLAY_ONLY:
        assert len(d.shown) == 1 and d.asked == 0
    else:
        assert d.asked == 1 and d.shown == []
    if sc:  # 20 confirm/random rounds from the host
        tx = host_tx_smp(ctl)
        assert sum(p[0] == CODE.PAIRING_CONFIRM for p in tx) == 20
        assert sum(p[0] == CODE.PAIRING_RANDOM for p in tx) == 20


def test_key_size_negotiation_masks_key():
    ctl, h, smp, peer, d, _ = make(True, peer_kw=dict(max_key=7))
    smp.pair(HANDLE)
    run(h, smp)
    r = assert_success(smp, peer, True, JUST_WORKS)
    assert r.key_size == 7 and r.stk_or_ltk[7:] == bytes(9)


def test_no_bonding_distributes_no_keys():
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(bonding=False))
    smp.pair(HANDLE)
    run(h, smp)
    r = assert_success(smp, peer, True, JUST_WORKS)
    assert not r.bonded and peer.keys_from_host == {} and smp.bonds == {}


def test_peripheral_security_request_triggers_peer_pairing():
    ctl, h, smp, peer, d, _ = make(False)
    smp.pair(HANDLE)   # peripheral -> Security Request
    assert host_tx_smp(ctl)[0] == bytes([CODE.SECURITY_REQUEST, AUTH_BONDING | AUTH_SC])
    run(h, smp)
    assert_success(smp, peer, True, JUST_WORKS)


@pytest.mark.parametrize("sc", [False, True])
def test_reencrypt_with_bond_central(sc):
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(sc=sc), peer_kw=dict(auth=SC_AUTH if sc else LEGACY_AUTH))
    smp.pair(HANDLE)
    run(h, smp)
    assert smp.results[HANDLE].success
    # emulate a reconnection: link encrypted again from the stored bond
    smp.encrypt(HANDLE)
    ncmds = len(ctl.cmds)
    h.pump(1)
    h.pump(1)
    start_enc = [c for c in ctl.cmds[ncmds:] if struct.unpack_from("<H", c)[0] == OP.LE_START_ENCRYPTION]
    assert len(start_enc) == 1
    ltk = start_enc[0][15:31]
    if sc:
        assert ltk == smp.results[HANDLE].stk_or_ltk and start_enc[0][13:15] == b"\0\0"
    else:
        assert ltk == peer.dist_ltk[0]
    assert ctl.encrypted[HANDLE] == ltk


def test_reencrypt_peripheral_ltk_lookup_by_ediv_rand():
    ctl, h, smp, peer, d, _ = make(False, SmpConfig(sc=False), peer_kw=dict(auth=LEGACY_AUTH))
    peer.start()
    run(h, smp)
    assert smp.results[HANDLE].success
    bond = next(iter(smp.bonds.values()))
    ctl.peer_start_encryption(HANDLE, bond.local.ltk, bond.local.ediv, bond.local.rand)
    h.pump(1)
    h.pump(1)
    assert ctl.encrypted[HANDLE] == bond.local.ltk
    ctl.peer_start_encryption(HANDLE, bond.local.ltk, 0x1234 ^ bond.local.ediv, bond.local.rand)
    h.pump(1)
    h.pump(1)
    assert any(struct.unpack_from("<H", c)[0] == OP.LE_LTK_REQUEST_NEG_REPLY for c in ctl.cmds)


# ------------------------------------------------------------------ failure paths
def failed(smp, reason, remote=False):
    r = smp.results[HANDLE]
    assert not r.success and r.reason == reason and r.remote == remote, str(r)
    assert smp.errors == 0
    return r


@ROLES
@pytest.mark.parametrize("sc", [False, True], ids=["legacy", "sc"])
def test_wrong_confirm_value(host_central, sc):
    if sc and not host_central:
        # SC Just Works: the initiator sends no confirm -> use passkey so the peer's Cai is checked
        cfg = SmpConfig(io_cap=IO.KEYBOARD_ONLY, mitm=True)
        kw = dict(io=IO.DISPLAY_ONLY, auth=SC_AUTH | AUTH_MITM, corrupt_confirm=True)
    else:
        cfg = SmpConfig(sc=sc)
        kw = dict(auth=SC_AUTH if sc else LEGACY_AUTH, corrupt_confirm=True)
    ctl, h, smp, peer, d, _ = make(host_central, cfg, peer_kw=kw)
    start(host_central, h, smp, peer)
    run(h, smp)
    failed(smp, REASON.CONFIRM_VALUE_FAILED)
    assert peer.host_failed == REASON.CONFIRM_VALUE_FAILED
    assert HANDLE not in smp.encrypted


@pytest.mark.parametrize("sc", [False, True], ids=["legacy", "sc"])
def test_passkey_mismatch(sc):
    auth = (SC_AUTH if sc else LEGACY_AUTH) | AUTH_MITM
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(io_cap=IO.KEYBOARD_ONLY, mitm=True, sc=sc),
                                   peer_kw=dict(io=IO.DISPLAY_ONLY, auth=auth), passkey_override=111111)
    smp.pair(HANDLE)
    run(h, smp)
    r = smp.results[HANDLE]
    assert not r.success and r.reason == REASON.CONFIRM_VALUE_FAILED
    assert peer.displayed_passkey != 111111


@ROLES
def test_numeric_comparison_rejected_by_user(host_central):
    ctl, h, smp, peer, d, _ = make(host_central, SmpConfig(io_cap=IO.DISPLAY_YES_NO, mitm=True),
                                   peer_kw=dict(io=IO.DISPLAY_YES_NO, auth=SC_AUTH | AUTH_MITM), nc_accept=False)
    start(host_central, h, smp, peer)
    run(h, smp)
    failed(smp, REASON.NUMERIC_COMPARISON_FAILED)


def test_peer_rejects_numeric_comparison():
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(io_cap=IO.DISPLAY_YES_NO, mitm=True),
                                   peer_kw=dict(io=IO.DISPLAY_YES_NO, auth=SC_AUTH | AUTH_MITM, nc_accept=False))
    smp.pair(HANDLE)
    run(h, smp)
    failed(smp, REASON.NUMERIC_COMPARISON_FAILED, remote=True)


@ROLES
def test_dhkey_check_failure(host_central):
    ctl, h, smp, peer, d, _ = make(host_central, peer_kw=dict(corrupt_dhkey_check=True))
    start(host_central, h, smp, peer)
    run(h, smp)
    failed(smp, REASON.DHKEY_CHECK_FAILED)


@ROLES
def test_invalid_public_key(host_central):
    ctl, h, smp, peer, d, _ = make(host_central, peer_kw=dict(bad_public_key=True))
    start(host_central, h, smp, peer)
    run(h, smp)
    failed(smp, REASON.DHKEY_CHECK_FAILED)


def test_reflected_public_key():
    ctl, h, smp, peer, d, _ = make(True, peer_kw=dict(reflect_public_key=True))
    smp.pair(HANDLE)
    run(h, smp)
    failed(smp, REASON.DHKEY_CHECK_FAILED)


@ROLES
def test_timeout_30s(host_central):
    ctl, h, smp, peer, d, clock = make(host_central, peer_kw=dict(silent_on=(CODE.PUBLIC_KEY,)))
    start(host_central, h, smp, peer)
    run(h, smp, n=5)
    assert HANDLE not in smp.results
    clock.t += 29.9
    h.pump(1)
    assert HANDLE not in smp.results
    clock.t += 0.2
    h.pump(1)
    r = smp.results[HANDLE]
    assert r.timeout and not r.success and smp.state(HANDLE) == "timeout"
    n = len(host_tx_smp(ctl))
    assert host_tx_smp(ctl)[-1][0] != CODE.PAIRING_FAILED  # 3.4: nothing sent on timeout
    peer.silent = False
    peer.inject(bytes([CODE.PAIRING_CONFIRM]) + bytes(16))
    peer.inject(bytes([CODE.PAIRING_REQUEST, 3, 0, 1, 16, 7, 7]))
    h.pump(1)
    assert len(host_tx_smp(ctl)) == n   # SMP stays silent on this link after a timeout


def test_timer_resets_on_each_sent_pdu():
    ctl, h, smp, peer, d, clock = make(True, SmpConfig(io_cap=IO.KEYBOARD_ONLY, mitm=True),
                                       peer_kw=dict(io=IO.DISPLAY_ONLY, auth=SC_AUTH | AUTH_MITM))
    smp.pair(HANDLE)
    for _ in range(100):  # advance 5 s per pump: total far beyond 30 s, but each step < 30 s
        clock.t += 5
        h.pump(1)
        if HANDLE in smp.results:
            break
    assert smp.results[HANDLE].success


def test_peer_sends_pairing_failed():
    ctl, h, smp, peer, d, _ = make(True, peer_kw=dict(silent_on=(CODE.PAIRING_REQUEST,)))
    smp.pair(HANDLE)
    peer.silent = False
    peer.inject(bytes([CODE.PAIRING_FAILED, REASON.PAIRING_NOT_SUPPORTED]))
    run(h, smp)
    failed(smp, REASON.PAIRING_NOT_SUPPORTED, remote=True)
    assert host_tx_smp(ctl)[-1][0] == CODE.PAIRING_REQUEST  # never answer a Pairing Failed


def _peer_silent_after_request(host_central=True, cfg=None, **kw):
    ctl, h, smp, peer, d, clock = make(host_central, cfg, peer_kw=dict(silent_on=(CODE.PAIRING_REQUEST,), **kw))
    smp.pair(HANDLE)
    peer.silent = False
    return ctl, h, smp, peer


@pytest.mark.parametrize("pdu,reason", [
    (bytes([CODE.PAIRING_RESPONSE, 3, 0, 9, 16, 7]), REASON.INVALID_PARAMETERS),             # short
    (bytes([CODE.PAIRING_RESPONSE, 3, 0, 9, 16, 7, 7, 0]), REASON.INVALID_PARAMETERS),       # long
    (bytes([CODE.PAIRING_RESPONSE, 9, 0, 9, 16, 7, 7]), REASON.INVALID_PARAMETERS),          # IO cap 9
    (bytes([CODE.PAIRING_RESPONSE, 3, 2, 9, 16, 7, 7]), REASON.INVALID_PARAMETERS),          # OOB 2
    (bytes([CODE.PAIRING_RESPONSE, 3, 0, 9, 17, 7, 7]), REASON.INVALID_PARAMETERS),          # key 17
    (bytes([CODE.PAIRING_RESPONSE, 3, 0, 9, 6, 7, 7]), REASON.ENCRYPTION_KEY_SIZE),          # key 6
    (bytes([CODE.PAIRING_RESPONSE, 3, 0, 9, 16, 0x0F, 7]), REASON.INVALID_PARAMETERS),       # unrequested kd
    (bytes([CODE.PAIRING_RESPONSE, 3, 1, 9, 16, 7, 7]), REASON.OOB_NOT_AVAILABLE),           # SC + OOB
    (bytes([CODE.PAIRING_RANDOM]) + bytes(16), REASON.UNSPECIFIED),                          # out of order
    (bytes([CODE.DHKEY_CHECK]) + bytes(16), REASON.UNSPECIFIED),                             # out of order
    (bytes([CODE.ENCRYPTION_INFO]) + bytes(16), REASON.UNSPECIFIED),                         # out of order
    (bytes([0x20, 1, 2, 3]), REASON.COMMAND_NOT_SUPPORTED),                                  # unknown code
    (bytes([0x00]), REASON.COMMAND_NOT_SUPPORTED),                                           # code 0 (RFU)
    (b"", REASON.INVALID_PARAMETERS),                                                        # empty
    (bytes([CODE.PUBLIC_KEY]) + bytes(63), REASON.INVALID_PARAMETERS),                       # short pk
    (bytes([CODE.KEYPRESS, 0]), REASON.UNSPECIFIED),                                         # not negotiated
])
def test_malformed_or_out_of_order_yields_pairing_failed(pdu, reason):
    ctl, h, smp, peer = _peer_silent_after_request()
    peer.inject(pdu)
    run(h, smp)
    failed(smp, reason)
    assert host_tx_smp(ctl)[-1] == bytes([CODE.PAIRING_FAILED, reason])
    assert peer.host_failed == reason


def test_unsupported_mitm_requirement():
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(mitm=True, io_cap=IO.DISPLAY_YES_NO))
    smp.pair(HANDLE)
    run(h, smp)
    failed(smp, REASON.AUTH_REQUIREMENTS)   # peer is NoInputNoOutput -> Just Works only


def test_sc_only_refuses_legacy_peer():
    ctl, h, smp, peer, d, _ = make(False, SmpConfig(sc_only=True), peer_kw=dict(auth=LEGACY_AUTH))
    peer.start()
    run(h, smp)
    failed(smp, REASON.AUTH_REQUIREMENTS)


def test_pairing_disabled_on_peripheral():
    ctl, h, smp, peer, d, _ = make(False, SmpConfig(accept_pairing=False))
    peer.start()
    run(h, smp)
    failed(smp, REASON.PAIRING_NOT_SUPPORTED)


def test_peer_key_too_small():
    ctl, h, smp, peer, d, _ = make(False, peer_kw=dict(max_key=6))
    peer.start()
    run(h, smp)
    failed(smp, REASON.ENCRYPTION_KEY_SIZE)


def test_passkey_entry_cancelled():
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(io_cap=IO.KEYBOARD_ONLY, mitm=True),
                                   peer_kw=dict(io=IO.DISPLAY_ONLY, auth=SC_AUTH | AUTH_MITM))
    d.request_passkey = lambda handle: None
    smp.pair(HANDLE)
    run(h, smp)
    failed(smp, REASON.PASSKEY_ENTRY_FAILED)


def test_encryption_ltk_mismatch_disconnect():
    ctl, h, smp, peer, d, _ = make(True)
    peer.on_ltk_request = lambda ediv, rand: bytes(16)   # peer's LL holds a different key
    smp.pair(HANDLE)
    run(h, smp)
    r = smp.results[HANDLE]
    assert not r.success and "disconnected reason 0x3d" in r.detail


def test_encryption_key_missing():
    ctl, h, smp, peer, d, _ = make(True)
    peer.on_ltk_request = lambda ediv, rand: None
    smp.pair(HANDLE)
    run(h, smp)
    r = smp.results[HANDLE]
    assert not r.success and "0x06" in r.detail


def test_out_of_order_key_distribution():
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(sc=False), peer_kw=dict(auth=LEGACY_AUTH))

    def swap(pdu):  # peer sends Identity Info where Encryption Info is due
        return bytes([CODE.IDENTITY_INFO]) + pdu[1:] if pdu[0] == CODE.ENCRYPTION_INFO else pdu
    peer.mutate = swap
    smp.pair(HANDLE)
    run(h, smp)
    failed(smp, REASON.UNSPECIFIED)


def test_keypress_notifications_when_negotiated():
    ctl, h, smp, peer, d, _ = make(False, SmpConfig(io_cap=IO.KEYBOARD_ONLY, mitm=True, keypress=True),
                                   peer_kw=dict(io=IO.DISPLAY_ONLY, auth=SC_AUTH | AUTH_MITM | AUTH_KEYPRESS,
                                                silent_on=(CODE.PUBLIC_KEY,)))
    peer.start()
    run(h, smp, n=5)
    peer.silent = False
    peer.inject(bytes([CODE.KEYPRESS, 1]))
    peer.inject(bytes([CODE.KEYPRESS, 4]))
    h.pump(1)
    assert d.keypresses == [1, 4] and HANDLE not in smp.results
    peer.inject(bytes([CODE.KEYPRESS, 7]))
    h.pump(1)
    failed(smp, REASON.INVALID_PARAMETERS)


def test_early_key_distribution_is_buffered_until_encryption_change():
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(sc=False), peer_kw=dict(auth=LEGACY_AUTH))
    real = ctl._link_encrypt

    def deliver_acl_first(handle, host_ltk, peer_ltk):  # peer's keys overtake Encryption Change
        n = len(ctl.events)
        real(handle, host_ltk, peer_ltk)
        ev = [e for e in ctl.events[n:] if e[0] == EVT.ENCRYPTION_CHANGE]
        for e in ev:
            ctl.events.remove(e)
        ctl._late = ev
    ctl._link_encrypt = deliver_acl_first
    smp.pair(HANDLE)
    run(h, smp, until=lambda: getattr(ctl, "_late", None) is not None and not ctl.acl_out)
    h.pump(1)
    assert HANDLE not in smp.results
    ctl.events += ctl._late
    run(h, smp)
    assert_success(smp, peer, False, JUST_WORKS)


def test_bredr_smp_refused():
    ctl = FakeController()
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.3)
    h.init_standard()
    ctl.connect_bredr(0x41)
    h.pump(1)
    l2 = L2cap(h)
    smp = Smp(h, l2)
    ctl.send_l2cap(0x41, CID_BREDR_SMP, bytes([CODE.PAIRING_REQUEST, 3, 0, 0x2D, 16, 0x0F, 0x0F]))
    h.pump(1)
    out = []
    r = L2capReassembler(lambda hh, c, p: out.append((c, p)))
    for p in ctl.acl_in:
        r.feed(p)
    assert out == [(CID_BREDR_SMP, bytes([CODE.PAIRING_FAILED, REASON.PAIRING_NOT_SUPPORTED]))]
    assert smp.errors == 0


def test_smp_on_le_cid_from_bredr_handle_ignored():
    ctl = FakeController()
    h = Hci(FakeTransport(ctl), cmd_timeout_s=0.3)
    h.init_standard()
    ctl.connect_bredr(0x41)
    h.pump(1)
    smp = Smp(h, L2cap(h))
    ctl.send_l2cap(0x41, CID_SMP, bytes([CODE.PAIRING_REQUEST, 3, 0, 1, 16, 7, 7]))
    h.pump(1)
    assert ctl.acl_in == [] and smp.errors == 0


# ------------------------------------------------------------------ method table
def test_method_table_matches_independent_rules():
    for i, r, sc, mitm in itertools.product(range(5), range(5), (False, True), (False, True)):
        assert select_method(i, r, sc, mitm) == FakeSmpPeer.method(i, r, sc, mitm), (i, r, sc, mitm)


def test_method_table_spot_checks():
    assert select_method(IO.DISPLAY_YES_NO, IO.DISPLAY_YES_NO, False, True) == (JUST_WORKS, None)
    assert select_method(IO.DISPLAY_YES_NO, IO.DISPLAY_YES_NO, True, True) == (NUMERIC_COMPARISON, None)
    assert select_method(IO.KEYBOARD_ONLY, IO.DISPLAY_ONLY, True, True) == (PASSKEY, "initiator_inputs")
    assert select_method(IO.KEYBOARD_DISPLAY, IO.KEYBOARD_DISPLAY, False, True) == (PASSKEY, "responder_inputs")
    assert select_method(IO.KEYBOARD_DISPLAY, IO.KEYBOARD_ONLY, True, False) == (JUST_WORKS, None)


# ------------------------------------------------------------------ robustness
@ROLES
def test_random_pdus_never_crash(host_central):
    """Software-only fuzz against the *host stack* (never a real device)."""
    rnd = random.Random(1234)
    codes = list(range(0x00, 0x10)) + [0x20, 0xFF]
    for trial in range(60):
        ctl, h, smp, peer, d, clock = make(host_central, seed=trial)
        start(host_central, h, smp, peer)
        run(h, smp, n=rnd.randrange(0, 6))
        peer.silent = False
        for _ in range(rnd.randrange(1, 6)):
            c = rnd.choice(codes)
            ln = PDU_LEN.get(c, 4) - 1 + rnd.choice([0, 0, 0, -1, 1, -5])
            peer.inject(bytes([c]) + bytes(rnd.getrandbits(8) for _ in range(max(0, ln))))
            h.pump(1)
        run(h, smp, n=20)
        assert smp.errors == 0, trial
        for pdu in host_tx_smp(ctl):  # whatever we sent is a well-formed SMP PDU
            assert pdu[0] in PDU_LEN and len(pdu) == PDU_LEN[pdu[0]]


@ROLES
def test_sc_confirm_is_sent_before_random(host_central):
    """Regression: the initiator must send Ca (0x03) before Na (0x04).

    The stack used to move straight to WAIT_CONFIRM in the JW/NC initiator path,
    so Ca was never put on the air and the peer had nothing to verify.
    """
    ctl, h, smp, peer, d, _ = make(host_central)
    start(host_central, h, smp, peer)
    run(h, smp)
    assert_success(smp, peer, True, JUST_WORKS)
    codes = [p[0] for p in host_tx_smp(ctl)]
    assert 0x03 in codes, codes
    assert codes.index(0x03) < codes.index(0x04), codes


# --------------------------------------------------- peer confirm quirk (f4 X-cross)
@ROLES
def test_f4_xcross_interoperates_with_quirk_peer(host_central):
    """The peer builds the confirm as f4(own_x, peer_x, rnd, z); f4_xcross must pair with it."""
    ctl, h, smp, peer, d, _ = make(host_central, SmpConfig(f4_xcross=True),
                                   peer_kw=dict(f4_xcross=True))
    start(host_central, h, smp, peer)
    run(h, smp)
    assert_success(smp, peer, True, JUST_WORKS)


def test_spec_host_rejects_xcross_peer():
    """Without the quirk flag a spec-compliant host cannot verify the peer-style confirm.

    Only the initiator path verifies the peer's confirm here (the responder path defers),
    so this is central-only.
    """
    ctl, h, smp, peer, d, _ = make(True, peer_kw=dict(f4_xcross=True))
    start(True, h, smp, peer)
    run(h, smp)
    failed(smp, REASON.CONFIRM_VALUE_FAILED)


def test_eager_encrypt_still_distributes_keys():
    """eager_encrypt must not skip key distribution (it registers the encryption waiter)."""
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(eager_encrypt=True))
    start(True, h, smp, peer)
    run(h, smp)
    r = assert_success(smp, peer, True, JUST_WORKS)
    assert r.remote_keys.irk is not None or r.remote_keys.identity_addr is not None
    assert peer.keys_from_host, "host distributed no keys after eager encryption"


def test_keys_first_still_completes_pairing():
    """keys_first sends the initiator's keys immediately; the pairing must still finish."""
    ctl, h, smp, peer, d, _ = make(True, SmpConfig(keys_first=True))
    start(True, h, smp, peer)
    run(h, smp)
    assert_success(smp, peer, True, JUST_WORKS)
    assert peer.keys_from_host
