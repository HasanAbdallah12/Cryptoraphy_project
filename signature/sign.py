# signature/sign.py
# --------------------------------------------------
# Pure-Python Ed25519 signature (no cryptography lib)
# We explicitly hash the input with SHA-256 first (teacher requirement).
# Then we sign that hash using Ed25519 (which internally uses SHA-512).
# --------------------------------------------------

import os
import hashlib

# ---- Ed25519 constants ----
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod p

# Base point (x, y)
Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
B = (Bx, By)


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _sha256(m: bytes) -> bytes:
    return hashlib.sha256(m).digest()


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x & 1:
        x = P - x
    return x


def _edwards_add(P1, P2):
    (x1, y1) = P1
    (x2, y2) = P2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + D * x1 * x2 * y1 * y2) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - D * x1 * x2 * y1 * y2) % P
    return (x3, y3)


def _scalarmult(Pt, e: int):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(Pt, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, Pt)
    return Q


def _encode_int(n: int) -> bytes:
    return n.to_bytes(32, "little")


def _decode_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _encode_point(Pt) -> bytes:
    (x, y) = Pt
    bits = y.to_bytes(32, "little")
    # set highest bit to x parity
    bits_list = bytearray(bits)
    bits_list[31] |= (x & 1) << 7
    return bytes(bits_list)


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("Invalid public key length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    # verify x parity matches sign bit
    if ((int.from_bytes(s, "little") >> 255) & 1) != (x & 1):
        x = P - x
    return (x, y)


def generate_keypair():
    """
    Returns (public_key_bytes, private_key_bytes)
    private_key_bytes: 32 random bytes (seed)
    public_key_bytes: 32 bytes
    """
    sk = os.urandom(32)
    h = _sha512(sk)
    a = int.from_bytes(h[:32], "little")
    # clamp
    a &= (1 << 254) - 8
    a |= 1 << 254

    A = _scalarmult(B, a)
    pk = _encode_point(A)
    return pk, sk


def sign(message_bytes: bytes, private_key_seed: bytes) -> bytes:
    """
    Ed25519 signature (64 bytes).
    We explicitly hash the message with SHA-256 first for the teacher.
    private_key_seed must be 32 bytes (the Ed25519 seed).
    """
    if len(private_key_seed) != 32:
        raise ValueError("Ed25519 private key seed must be 32 bytes")

    # explicit teacher hash
    msg = _sha256(message_bytes)

    h = _sha512(private_key_seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]

    A = _encode_point(_scalarmult(B, a))

    r = int.from_bytes(_sha512(prefix + msg), "little") % L
    R = _encode_point(_scalarmult(B, r))

    k = int.from_bytes(_sha512(R + A + msg), "little") % L
    S = (r + k * a) % L

    return R + _encode_int(S)
