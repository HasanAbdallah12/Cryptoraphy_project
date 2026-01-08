# merkle_hellman/encrypt.py
# ----------------------------------
# Merkle–Hellman Encryption
# ----------------------------------


def encrypt(bits, public_key):
    """
    Encrypts a list of bits using Merkle–Hellman public key.
    bits MUST be length 8.
    """

    if len(bits) != len(public_key):
        raise ValueError("Bits length must match public key length")

    ciphertext = 0

    for i in range(len(bits)):
        if bits[i] == 1:
            ciphertext += public_key[i]

    return ciphertext
