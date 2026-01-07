

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
    Decrypt ciphertext using the Merkle–Hellman private key
    """

    w, q, r = private_key

    # 1. Compute modular inverse of r
    r_inv = mod_inverse(r, q)

    # 2. Undo modular multiplication
    s = (ciphertext * r_inv) % q

    # 3. Solve superincreasing knapsack (greedy)
    bits = [0] * len(w)

    for i in range(len(w) - 1, -1, -1):
        if w[i] <= s:
            bits[i] = 1
            s -= w[i]

    return bits
