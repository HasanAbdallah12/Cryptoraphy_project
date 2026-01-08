# serpent/serpent_core.py
# --------------------------------------------------
# Serpent block cipher (educational, real structure)
# --------------------------------------------------

MASK = 0xFFFFFFFF


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


# Real Serpent S-boxes
SBOX = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]
]


def apply_sbox(box, word):
    result = 0
    for i in range(8):  # 8 nibbles (32 bits)
        nibble = (word >> (i * 4)) & 0xF
        result |= box[nibble] << (i * 4)
    return result


def linear_transform(x0, x1, x2, x3):
    x0 = rotl(x0, 13)
    x2 = rotl(x2, 3)
    x1 ^= x0 ^ x2
    x3 ^= x2 ^ (x0 << 3)
    x1 = rotl(x1, 1)
    x3 = rotl(x3, 7)
    x0 ^= x1 ^ x3
    x2 ^= x3 ^ (x1 << 7)
    x0 = rotl(x0, 5)
    x2 = rotl(x2, 22)
    return x0, x1, x2, x3


def expand_key(key):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256-bit)")

    w = []
    for i in range(8):
        w.append(int.from_bytes(key[i*4:(i+1)*4], "little"))

    PHI = 0x9E3779B9
    for i in range(8, 140):
        v = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ (i - 8)
        w.append(rotl(v, 11))

    round_keys = []
    for r in range(33):
        k = w[4*r + 8:4*r + 12]
        s = SBOX[(32 - r) % 8]
        round_keys.append(tuple(apply_sbox(s, x) for x in k))

    return round_keys


def encrypt_block(block, round_keys):
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")

    x = [int.from_bytes(block[i*4:(i+1)*4], "little") for i in range(4)]

    for r in range(32):
        x = [x[i] ^ round_keys[r][i] for i in range(4)]
        s = SBOX[r % 8]
        x = [apply_sbox(s, w) for w in x]
        if r != 31:
            x = list(linear_transform(*x))

    x = [x[i] ^ round_keys[32][i] for i in range(4)]

    return b"".join(x[i].to_bytes(4, "little") for i in range(4))
