# serpent/cbc_mode.py
# --------------------------------------------------
# CBC mode for Serpent
# --------------------------------------------------

import os
from .serpent_core import encrypt_block, expand_key

BLOCK_SIZE = 16


def xor_bytes(a, b):
    result = bytearray()
    for i in range(len(a)):
        result.append(a[i] ^ b[i])
    return bytes(result)


def pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def encrypt_cbc(plaintext, key):
    round_keys = expand_key(key)
    plaintext = pad(plaintext)

    iv = os.urandom(BLOCK_SIZE)
    prev = iv
    ciphertext = b""

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        block = xor_bytes(block, prev)
        enc = encrypt_block(block, round_keys)
        ciphertext += enc
        prev = enc

    return iv, ciphertext
