# merkle_hellman/keygen.py
# ----------------------------------
# Merkle–Hellman Key Generation
# (8-bit educational version)
# ----------------------------------

import random
import math


def generate_superincreasing_sequence(length):
    sequence = []
    current_sum = 0

    for _ in range(length):
        next_number = random.randint(current_sum + 1, current_sum + 10)
        sequence.append(next_number)
        current_sum += next_number

    return sequence


def generate_keys(length=8):
    """
    Generates Merkle–Hellman keys for 'length' bits.
    Default = 8 bits (1 byte), which is REQUIRED for hybrid crypto.
    """

    # 1. Private super-increasing sequence
    w = generate_superincreasing_sequence(length)

    # 2. Modulus q > sum(w)
    total = sum(w)
    q = random.randint(total + 1, total + 50)

    # 3. Multiplier r, gcd(r, q) = 1
    r = random.randint(2, q - 1)
    while math.gcd(r, q) != 1:
        r = random.randint(2, q - 1)

    # 4. Public key
    public_key = [(r * wi) % q for wi in w]

    # 5. Private key
    private_key = (w, q, r)

    return public_key, private_key
