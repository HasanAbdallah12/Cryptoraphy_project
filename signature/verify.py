# signature/verify.py
# --------------------------------------------------
# Pure-Python Ed25519 verify (no cryptography lib)
# We explicitly SHA-256 the message first (teacher requirement).
# --------------------------------------------------

import hashlib

# Same constants + helpers as sign.py (must match)
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)

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
    bits_list = bytearray(bits)
    bits_list[31] |= (x & 1) << 7
    return bytes(bits_list)


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("Invalid public key length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if ((int.from_bytes(s, "little") >> 255) & 1) != (x & 1):
        x = P - x
    return (x, y)


def verify(message_bytes: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify Ed25519 signature.
    signature must be 64 bytes, public_key_bytes must be 32 bytes.
    """
    try:
        if len(signature) != 64 or len(public_key_bytes) != 32:
            return False

        # explicit teacher hash
        msg = _sha256(message_bytes)

        R_bytes = signature[:32]
        S_bytes = signature[32:]
        S = _decode_int(S_bytes)
        if S >= L:
            return False

        A = _decode_point(public_key_bytes)
        R = _decode_point(R_bytes)

        k = int.from_bytes(_sha512(R_bytes + public_key_bytes + msg), "little") % L

        # Check: [S]B == R + [k]A
        left = _scalarmult(B, S)
        right = _edwards_add(R, _scalarmult(A, k))

        return left == right
    except Exception:
        return False
