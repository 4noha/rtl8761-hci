"""SMP cryptographic toolbox (Core Vol 3 Part H 2.2): e, c1, s1, ah, f4, f5, f6, g2, h6, h7,
AES-CMAC and P-256 ECDH.

Byte order: every function takes and returns *over-the-air (little-endian)* byte strings,
exactly as they appear in SMP PDUs (same convention as Linux net/bluetooth/smp.c). The spec
writes values MSB-first; tests reverse the spec's hex strings before calling.

Backend: the `cryptography` package when importable, else a pure-Python AES-128 / CMAC /
P-256 implementation. Set RTLHCI_PURE_CRYPTO=1 to force the pure backend. Both are checked
against the same spec sample data in tests/test_smp_crypto.py.
"""
from __future__ import annotations

import os
from typing import Callable

# ----------------------------------------------------------------- backend select
_ForcePure = os.environ.get("RTLHCI_PURE_CRYPTO") == "1"
try:
    if _ForcePure:
        raise ImportError("forced pure backend")
    from cryptography.hazmat.primitives import cmac as _c_cmac
    from cryptography.hazmat.primitives.asymmetric import ec as _c_ec
    from cryptography.hazmat.primitives.ciphers import Cipher as _c_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _c_alg
    from cryptography.hazmat.primitives.ciphers import modes as _c_modes
    BACKEND = "cryptography"
except ImportError:
    BACKEND = "pure"


def rev(b: bytes) -> bytes:
    return bytes(b)[::-1]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ================================================================= pure AES-128 (FIPS-197)
def _build_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:  # p iterates the multiplicative group by 3, q by its inverse
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()


def _xt(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand_key(key: bytes) -> list[list[int]]:
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def _aes128_pure(key: bytes, block: bytes) -> bytes:
    rk = _expand_key(key)
    s = [b ^ k for b, k in zip(block, rk[0])]
    for rnd in range(1, 11):
        s = [_SBOX[x] for x in s]
        # ShiftRows (state is column-major: index = 4*col + row)
        s = [s[(4 * ((c + r) % 4)) + r] for c in range(4) for r in range(4)]
        if rnd != 10:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


def aes128(key: bytes, block: bytes) -> bytes:
    """Standard AES-128 encryption of one block (MSB-first, as in FIPS-197)."""
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 needs 16-byte key and block")
    if BACKEND == "cryptography":
        enc = _c_Cipher(_c_alg.AES(bytes(key)), _c_modes.ECB()).encryptor()
        return enc.update(bytes(block)) + enc.finalize()
    return _aes128_pure(bytes(key), bytes(block))


def _dbl(b: bytes) -> bytes:
    v = int.from_bytes(b, "big") << 1
    if v >> 128:
        v = (v ^ 0x87) & ((1 << 128) - 1)
    return v.to_bytes(16, "big")


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    """AES-CMAC (RFC 4493 / NIST SP 800-38B), MSB-first."""
    if BACKEND == "cryptography":
        c = _c_cmac.CMAC(_c_alg.AES(bytes(key)))
        c.update(bytes(msg))
        return c.finalize()
    l_ = aes128(key, bytes(16))
    k1 = _dbl(l_)
    k2 = _dbl(k1)
    n = max(1, (len(msg) + 15) // 16)
    last = msg[16 * (n - 1):]
    if len(msg) and len(last) == 16:
        last = xor(last, k1)
    else:
        last = xor(last + b"\x80" + bytes(15 - len(last)), k2)
    x = bytes(16)
    for i in range(n - 1):
        x = aes128(key, xor(x, msg[16 * i:16 * i + 16]))
    return aes128(key, xor(x, last))


# ================================================================= SMP functions (LE in/out)
def e(k: bytes, r: bytes) -> bytes:
    """Security function e (Vol 3 Part H 2.2.1) on LE byte strings."""
    return rev(aes128(rev(k), rev(r)))


def cmac_le(k: bytes, m: bytes) -> bytes:
    return rev(aes_cmac(rev(k), rev(m)))


def c1(k: bytes, r: bytes, preq: bytes, pres: bytes, iat: int, ia: bytes, rat: int,
       ra: bytes) -> bytes:
    """Legacy confirm value. preq/pres = the full 7-byte Pairing Request/Response PDUs,
    ia/ra = 6-byte LE addresses, iat/rat = address types (0 public, 1 random)."""
    p1 = bytes([iat & 1, rat & 1]) + bytes(preq) + bytes(pres)
    p2 = bytes(ra) + bytes(ia) + bytes(4)
    return e(k, xor(e(k, xor(r, p1)), p2))


def s1(k: bytes, r1: bytes, r2: bytes) -> bytes:
    """Legacy STK: s1(TK, Srand, Mrand)."""
    return e(k, bytes(r2[:8]) + bytes(r1[:8]))


def ah(irk: bytes, r: bytes) -> bytes:
    """Random address hash (3 bytes LE)."""
    return e(irk, bytes(r[:3]) + bytes(13))[:3]


def f4(u: bytes, v: bytes, x: bytes, z: int) -> bytes:
    return cmac_le(x, bytes([z]) + bytes(v) + bytes(u))


_F5_SALT = rev(bytes.fromhex("6c888391aaf5a53860370bdb5a6083be"))
_F5_KEYID = rev(b"btle")


def f5(w: bytes, n1: bytes, n2: bytes, a1: bytes, a2: bytes) -> tuple[bytes, bytes]:
    """-> (MacKey, LTK). a1/a2 = 7 bytes: 6-byte LE address + address type byte."""
    t = cmac_le(_F5_SALT, w)
    m = b"\x00\x01" + bytes(a2) + bytes(a1) + bytes(n2) + bytes(n1) + _F5_KEYID
    return cmac_le(t, m + b"\x00"), cmac_le(t, m + b"\x01")


def f6(w: bytes, n1: bytes, n2: bytes, r: bytes, iocap: bytes, a1: bytes, a2: bytes) -> bytes:
    """iocap = 3 bytes in PDU order: IO capability, OOB flag, AuthReq."""
    return cmac_le(w, bytes(a2) + bytes(a1) + bytes(iocap) + bytes(r) + bytes(n2) + bytes(n1))


def g2(u: bytes, v: bytes, x: bytes, y: bytes) -> int:
    """Numeric comparison value (0..999999)."""
    t = cmac_le(x, bytes(y) + bytes(v) + bytes(u))
    return int.from_bytes(t[:4], "little") % 1_000_000


def h6(w: bytes, key_id: bytes) -> bytes:
    """key_id given as ASCII, e.g. b'lebr' (MSB-first, as written in the spec)."""
    return cmac_le(w, rev(key_id))


def h7(salt: bytes, w: bytes) -> bytes:
    return cmac_le(salt, w)


# ================================================================= P-256
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Debug keys (Vol 3 Part H 2.3.5.6.1), LE as sent in the Public Key PDU.
DEBUG_PRIVATE_KEY = rev(bytes.fromhex(
    "3f49f6d4a3c55f3874c9b3e3d2103f504aff607beb40b7995899b8a6cd3c1abd"))
DEBUG_PUBLIC_KEY = rev(bytes.fromhex(
    "20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6")) + rev(bytes.fromhex(
    "dc809c49652aeb6d63329abf5a52155c766345c28fed3024741c8ed01589d28b"))


class InvalidPublicKey(ValueError):
    pass


def on_curve(x: int, y: int) -> bool:
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _jdouble(X, Y, Z):
    if Y == 0:
        return 0, 1, 0
    YY = Y * Y % P
    S = 4 * X * YY % P
    ZZ = Z * Z % P
    M = 3 * (X - ZZ) * (X + ZZ) % P  # a = -3
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * YY * YY) % P
    return X3, Y3, 2 * Y * Z % P


def _jadd(X1, Y1, Z1, X2, Y2, Z2):
    if Z1 == 0:
        return X2, Y2, Z2
    if Z2 == 0:
        return X1, Y1, Z1
    Z1Z1, Z2Z2 = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2Z2 % P, X2 * Z1Z1 % P
    S1, S2 = Y1 * Z2 * Z2Z2 % P, Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        return _jdouble(X1, Y1, Z1) if S1 == S2 else (0, 1, 0)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - S1 * HHH) % P
    return X3, Y3, H * Z1 * Z2 % P


def _mul(k: int, x: int, y: int) -> tuple[int, int]:
    R = (0, 1, 0)
    for bit in bin(k)[2:]:
        R = _jdouble(*R)
        if bit == "1":
            R = _jadd(*R, x, y, 1)
    X, Y, Z = R
    if Z == 0:
        raise InvalidPublicKey("point at infinity")
    zi = pow(Z, -1, P)
    return X * zi * zi % P, Y * zi * zi * zi % P


def _split_pub(pub: bytes) -> tuple[int, int]:
    if len(pub) != 64:
        raise InvalidPublicKey("public key must be 64 bytes")
    x, y = int.from_bytes(pub[:32], "little"), int.from_bytes(pub[32:], "little")
    if not on_curve(x, y):
        raise InvalidPublicKey("public key not on P-256")
    return x, y


def validate_public_key(pub: bytes) -> None:
    """Raise InvalidPublicKey unless `pub` (64 bytes LE X||Y) is a point on P-256."""
    _split_pub(pub)


def public_key(priv: bytes) -> bytes:
    """64-byte LE X||Y from a 32-byte LE private key."""
    d = int.from_bytes(priv, "little")
    if not 1 <= d < N:
        raise ValueError("private key out of range")
    if BACKEND == "cryptography":
        pn = _c_ec.derive_private_key(d, _c_ec.SECP256R1()).public_key().public_numbers()
        x, y = pn.x, pn.y
    else:
        x, y = _mul(d, GX, GY)
    return x.to_bytes(32, "little") + y.to_bytes(32, "little")


def generate_keypair(rng: Callable[[int], bytes] = os.urandom) -> tuple[bytes, bytes]:
    while True:
        d = int.from_bytes(rng(32), "big")
        if 1 <= d < N:
            priv = d.to_bytes(32, "little")
            return priv, public_key(priv)


def dhkey(priv: bytes, peer_pub: bytes) -> bytes:
    """ECDH shared secret (X coordinate, 32 bytes LE). Raises InvalidPublicKey."""
    x, y = _split_pub(peer_pub)
    d = int.from_bytes(priv, "little")
    if BACKEND == "cryptography":
        from cryptography.hazmat.primitives.asymmetric.ec import ECDH
        try:
            pk = _c_ec.EllipticCurvePublicNumbers(x, y, _c_ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise InvalidPublicKey(str(exc)) from exc
        sk = _c_ec.derive_private_key(d, _c_ec.SECP256R1())
        return rev(sk.exchange(ECDH(), pk))
    sx, _ = _mul(d, x, y)
    return sx.to_bytes(32, "little")


def mask_key(key: bytes, size: int) -> bytes:
    """Reduce a 128-bit key to `size` octets (upper octets zeroed, LE)."""
    return bytes(key[:size]) + bytes(16 - size)


class use_backend:
    """Context manager for tests: temporarily force 'pure' or 'cryptography'."""

    def __init__(self, name: str):
        self.name, self.saved = name, None

    def __enter__(self):
        global BACKEND
        if self.name == "cryptography" and "_c_ec" not in globals():
            raise RuntimeError("cryptography not available")
        self.saved, BACKEND = BACKEND, self.name
        return self

    def __exit__(self, *a):
        global BACKEND
        BACKEND = self.saved


__all__ = ["BACKEND", "aes128", "aes_cmac", "e", "c1", "s1", "ah", "f4", "f5", "f6", "g2", "h6",
           "h7", "public_key", "validate_public_key", "generate_keypair", "dhkey", "mask_key", "InvalidPublicKey",
           "DEBUG_PRIVATE_KEY", "DEBUG_PUBLIC_KEY", "rev", "use_backend"]
