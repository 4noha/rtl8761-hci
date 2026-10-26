"""SMP crypto against published sample data.

Values are written MSB-first exactly as printed in the Core spec, Vol 3 Part H:
  2.2.3 (c1), 2.2.4 (s1) worked examples, Appendix D (f4, f5, f6, g2, h6, ah), and the
  P-256 sample data / debug keys (2.3.5.6.1). They were taken from the copies in Linux
  net/bluetooth/smp.c and selftest.c, which reproduce the spec tables byte by byte.
Every test runs on the pure-Python backend and, if installed, on `cryptography`.
"""
import os

import pytest

from rtlhci import smp_crypto as C

M = lambda h: bytes.fromhex(h.replace(" ", ""))[::-1]   # spec MSB-first hex -> LE bytes

try:
    import cryptography  # noqa: F401
    BACKENDS = ["pure", "cryptography"]
except ImportError:
    BACKENDS = ["pure"]


@pytest.fixture(params=BACKENDS)
def backend(request):
    with C.use_backend(request.param):
        yield request.param


# ------------------------------------------------------------------ primitives
def test_aes128_fips197(backend):
    assert C.aes128(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")) == \
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


@pytest.mark.parametrize("mlen,mac", [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
])
def test_aes_cmac_rfc4493(backend, mlen, mac):
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")[:mlen]
    assert C.aes_cmac(key, msg) == bytes.fromhex(mac)


# ------------------------------------------------------------------ legacy
def test_c1_spec_example(backend):
    k = bytes(16)
    r = M("5783D52156AD6F0E6388274EC6702EE0")
    preq, pres = M("07071000000101"), M("05000800000302")
    ia, ra = M("A1A2A3A4A5A6"), M("B1B2B3B4B5B6")
    assert C.c1(k, r, preq, pres, 1, ia, 0, ra) == M("1E1E3FEF878988EAD2A74DC5BEF13B86")


def test_s1_spec_example(backend):
    r1 = M("000F0E0D0C0B0A091122334455667788")
    r2 = M("010203040506070899AABBCCDDEEFF00")
    assert C.s1(bytes(16), r1, r2) == M("9a1fe1f0e8b0f49b5b4216ae796da062")


def test_ah_appendix_d(backend):
    irk = M("ec0234a357c8ad05341010a60a397d9b")
    assert C.ah(irk, M("708194")) == M("0dfbaa")


# ------------------------------------------------------------------ secure connections
U = M("20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6")
V = M("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd")
X = M("d5cb8454 d177733e ffffb2ec 712baeab")
Y = M("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf")
W = M("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698")
A1, A2 = M("00561237 37bfce"), M("00a71370 2dcfc1")
MACKEY = M("2965f176 a1084a02 fd3f6a20 ce636e20")
LTK = M("69867911 69d7cd23 980522b5 94750a38")


def test_f4_appendix_d(backend):
    assert C.f4(U, V, X, 0) == M("f2c916f1 07a9bd1c f1eda1be a974872d")


def test_f5_appendix_d(backend):
    assert C.f5(W, X, Y, A1, A2) == (MACKEY, LTK)


def test_f6_appendix_d(backend):
    r = M("12a3343b b453bb54 08da42d2 0c2d0fc8")
    iocap = M("010102")
    assert C.f6(MACKEY, X, Y, r, iocap, A1, A2) == M("e3c47398 9cd0e8c5 d26c0b09 da958f61")


def test_g2_appendix_d(backend):
    assert C.g2(U, V, X, Y) == 0x2f9ed5ba % 1_000_000


def test_h6_appendix_d(backend):
    assert C.h6(M("ec0234a3 57c8ad05 341010a6 0a397d9b"), b"lebr") == \
        M("2d9ae102 e76dc91c e8d3a9e2 80b16399")


# ------------------------------------------------------------------ P-256
def P(x, y):
    return M(x) + M(y)


def test_debug_keypair(backend):
    assert C.public_key(C.DEBUG_PRIVATE_KEY) == C.DEBUG_PUBLIC_KEY
    assert C.DEBUG_PUBLIC_KEY[:32] == U   # f4 sample U is the debug public key X


ECDH_SETS = [
    ("3f49f6d4a3c55f3874c9b3e3d2103f504aff607beb40b7995899b8a6cd3c1abd",
     "55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd",
     P("1ea1f0f01faf1d9609592284f19e4c0047b58afd8615a69f559077b22faaa190",
       "4c55f33e429dad377356703a9ab85160472d1130e28e36765f89aff915b1214a"),
     "ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698"),
    ("06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663",
     "529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba",
     P("f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc",
       "0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279"),
     "ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69"),
]


@pytest.mark.parametrize("pa,pb,pub_b,dh", ECDH_SETS)
def test_ecdh_sample_data(backend, pa, pb, pub_b, dh):
    a, b = M(pa), M(pb)
    assert C.public_key(b) == pub_b
    assert C.dhkey(a, pub_b) == M(dh)
    assert C.dhkey(b, C.public_key(a)) == M(dh)


def test_ecdh_debug_self(backend):
    assert C.dhkey(C.DEBUG_PRIVATE_KEY, C.DEBUG_PUBLIC_KEY) == \
        M("70aad7e649f91c7cae5f79fc32992787c38757a8728b7b55da7bb3cb4800ab2d")


def test_f5_w_is_dhkey_of_sample_set_1():
    assert W == M(ECDH_SETS[0][3])


def test_invalid_points_rejected(backend):
    bad = C.DEBUG_PUBLIC_KEY[:32] + bytes([C.DEBUG_PUBLIC_KEY[32] ^ 1]) + C.DEBUG_PUBLIC_KEY[33:]
    for pk in (bad, bytes(64), b"\xff" * 64, C.DEBUG_PUBLIC_KEY[:63]):
        with pytest.raises(C.InvalidPublicKey):
            C.dhkey(C.DEBUG_PRIVATE_KEY, pk)


@pytest.mark.skipif("cryptography" not in BACKENDS, reason="cryptography not installed")
def test_backends_agree_on_random_inputs():
    for _ in range(5):
        k, m = os.urandom(16), os.urandom(os.urandom(1)[0] % 80)
        d = os.urandom(32)
        with C.use_backend("pure"):
            p1 = (C.aes_cmac(k, m), C.e(k, m[:16].ljust(16, b"\0")))
            priv, pub = C.generate_keypair(lambda n: d)
            o_priv, o_pub = C.generate_keypair()
            s1 = C.dhkey(priv, o_pub)
        with C.use_backend("cryptography"):
            p2 = (C.aes_cmac(k, m), C.e(k, m[:16].ljust(16, b"\0")))
            assert C.public_key(priv) == pub
            assert C.dhkey(o_priv, pub) == s1
        assert p1 == p2


def test_mask_key():
    k = bytes(range(1, 17))
    assert C.mask_key(k, 7) == bytes(range(1, 8)) + bytes(9)
    assert C.mask_key(k, 16) == k
