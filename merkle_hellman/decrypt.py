# merkle_hellman/decrypt.py
# ----------------------------------
# Merkle–Hellman Decryption
# ----------------------------------

import math


def mod_inverse(r, q):
    """
    Compute modular inverse of r modulo q
    """
    for i in range(1, q):
        if (r * i) % q == 1:
            return i
    raise ValueError("No modular inverse found")


def decrypt(ciphertext, private_key):
    """
    Decrypts a Merkle–Hellman ciphertext.
    Returns a list of bits (length 8).
    """

    w, q, r = private_key

    # 1. Compute r inverse
    r_inv = mod_inverse(r, q)

    # 2. Undo modular multiplication
    s = (ciphertext * r_inv) % q

    # 3. Solve super-increasing knapsack
    bits = [0] * len(w)

    for i in range(len(w) - 1, -1, -1):
        if w[i] <= s:
            bits[i] = 1
            s -= w[i]

    return bits
