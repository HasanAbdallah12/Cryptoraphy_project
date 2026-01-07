# merkle_hellman/keygen.py
# ----------------------------------
# Merkle–Hellman Key Generation
# ----------------------------------

import random
import math


def generate_superincreasing_sequence(length):
    # This list will hold the increasing numbers
    sequence = []

    # This keeps track of the sum of previous numbers
    current_sum = 0

    # Create numbers one by one
    for i in range(length):
        # Pick a number larger than the sum so far
        next_number = random.randint(current_sum + 1, current_sum + 10)

        # Add it to the list
        sequence.append(next_number)

        # Update the sum
        current_sum = current_sum + next_number

    return sequence


def generate_keys(length=8):
    # 1. Create the secret increasing sequence
    secret_sequence = generate_superincreasing_sequence(length)

    # 2. Choose a number larger than the sum of the sequence
    total = sum(secret_sequence)
    big_number = random.randint(total + 1, total + 50)

    # 3. Choose a mixing number that can be reversed
    mixing_number = random.randint(2, big_number - 1)

    while math.gcd(mixing_number, big_number) != 1:
        mixing_number = random.randint(2, big_number - 1)

    # 4. Create the public key by mixing each secret number
    public_key = []

    for value in secret_sequence:
        mixed_value = (mixing_number * value) % big_number
        public_key.append(mixed_value)

    # 5. Private key contains everything needed to decode
    private_key = (secret_sequence, big_number, mixing_number)

    return public_key, private_key
