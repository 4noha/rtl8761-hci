from rtlhci import smp_crypto as C

def h(s): return bytes.fromhex(s)

def test_f4_vector():
    u = h("e69d350e480103ccdbfdf4ac1191f4efb9a5f9e9a7832c5e2cbe97f2d203b020")
    v = h("fdc57ff449dd4f6bfb7c9df1c29acb592ae7d4eefbfc0a909abbf6323d8b1855")
    x = h("abae2b71ecb2ffff3e7377d15484cbd5")
    assert C.f4(u, v, x, 0x00) == h("2d8774a9bea1edf11cbda907f116c9f2")

def test_f5_vector():
    w = h("98a6bf73f3348d86f166f8b4136b79999b7d390aa610103405adc857a33402ec")
    n1 = h("abae2b71ecb2ffff3e7377d15484cbd5")
    n2 = h("cfc43dfff78365216e5fa725cce7e8a6")
    a1 = h("cebf3737125600")
    a2 = h("c1cf2d7013a700")
    mackey, ltk = C.f5(w, n1, n2, a1, a2)
    assert mackey == h("206e63ce206a3ffd024a08a176f16529")
    assert ltk == h("380a7594b522059823cdd76911798669")

def test_f6_vector():
    w = h("206e63ce206a3ffd024a08a176f16529")
    n1 = h("abae2b71ecb2ffff3e7377d15484cbd5")
    n2 = h("cfc43dfff78365216e5fa725cce7e8a6")
    r = h("c80f2d0cd242da0854bb53b43b34a312")
    io = h("020101")
    a1 = h("cebf3737125600")
    a2 = h("c1cf2d7013a700")
    assert C.f6(w, n1, n2, r, io, a1, a2) == h("618f95da090b6cd2c5e8d09c9873c4e3")

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def test_public_key_is_on_curve():
    from rtlhci import smp_crypto as C

    def on_curve(x, y):
        return (y * y - (x * x * x + _A * x + _B)) % P == 0

    priv = bytes.fromhex("bd1a3ccda6b8995899b740eb7b60ff4a503f10d2e3b3c974385fc5a3d4f6493f")
    pub = C.public_key(priv)
    x = int.from_bytes(pub[:32], "little")
    y = int.from_bytes(pub[32:], "little")
    assert on_curve(x, y)


def test_confirm_uses_x_then_y():
    """Ca must be f4(PKx, PKy, Na, 0); swapping the coordinate order changes it."""
    from rtlhci import smp_crypto as C

    priv = bytes.fromhex("bd1a3ccda6b8995899b740eb7b60ff4a503f10d2e3b3c974385fc5a3d4f6493f")
    pub = C.public_key(priv)
    na = bytes(range(16))
    xy = C.f4(pub[:32], pub[32:], na, 0)
    yx = C.f4(pub[32:], pub[:32], na, 0)
    assert xy != yx
    # our implementation must be the X||Y form used by the spec
    assert xy == C.f4(pub[:32], pub[32:], na, 0) and xy != yx
