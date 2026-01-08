# demo.py
# ==================================================
# Secure SMS Exchange Demo
# SERPENT (CBC) + Merkle–Hellman + Ed25519 Signature
# ==================================================

import os
import sys
import hashlib

# --------------------------------------------------
# Make project root visible (Spyder / Windows safe)
# --------------------------------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------
# Imports (YOUR FILES)
# --------------------------------------------------
from serpent.cbc_mode import encrypt_cbc

from merkle_hellman.keygen import generate_keys
from merkle_hellman.encrypt import encrypt as mh_encrypt
from merkle_hellman.decrypt import decrypt as mh_decrypt

from signature.sign import sign, generate_keypair
from signature.verify import verify


# --------------------------------------------------
# Helper functions (seed ↔ bits ↔ key)
# --------------------------------------------------
def byte_to_bits(b):
    return [(b >> i) & 1 for i in range(8)]


def bits_to_byte(bits):
    value = 0
    for i in range(8):
        value |= bits[i] << i
    return value


def derive_serpent_key(seed_byte):
    """
    Teacher-allowed: hash used for key derivation
    """
    return hashlib.sha256(bytes([seed_byte])).digest()


# --------------------------------------------------
# MAIN DEMO
# --------------------------------------------------
def main():
    print("===== SECURE SMS EXCHANGE DEMO =====\n")

    # ==================================================
    # RECEIVER: Merkle–Hellman key generation
    # ==================================================
    mh_public_key, mh_private_key = generate_keys(length=8)

    print("[1] Merkle–Hellman keys generated (receiver)")
    print("    Public key:", mh_public_key)
    print()

    # ==================================================
    # SENDER: generate 1-byte seed
    # ==================================================
    seed_byte = os.urandom(1)[0]
    seed_bits = byte_to_bits(seed_byte)

    print("[2] Sender generated random seed byte")
    print("    Seed byte:", seed_byte)
    print("    Seed bits:", seed_bits)
    print()

    # ==================================================
    # SENDER: encrypt seed with Merkle–Hellman
    # ==================================================
    encrypted_seed = mh_encrypt(seed_bits, mh_public_key)

    print("[3] Seed encrypted with Merkle–Hellman")
    print("    Encrypted seed:", encrypted_seed)
    print()

    # ==================================================
    # SENDER: derive Serpent key from seed
    # ==================================================
    serpent_key = derive_serpent_key(seed_byte)

    print("[4] Serpent key derived from seed (SHA-256)")
    print("    Serpent key length:", len(serpent_key), "bytes")
    print()

    # ==================================================
    # SENDER: encrypt message with Serpent + CBC
    # ==================================================
    message = b"HELLO THIS IS A SECURE SMS MESSAGE"

    iv, ciphertext = encrypt_cbc(message, serpent_key)

    print("[5] Message encrypted using Serpent + CBC")
    print("    IV:", iv.hex())
    print("    Ciphertext:", ciphertext.hex())
    print()

    # ==================================================
    # SENDER: generate Ed25519 signing keys
    # ==================================================
    public_sign_key, private_sign_key = generate_keypair()

    print("[6] Ed25519 signing keys generated (sender)")
    print()

    # ==================================================
    # SENDER: sign transmitted data
    # ==================================================
    data_to_sign = iv + ciphertext + encrypted_seed.to_bytes(4, "big")

    signature = sign(data_to_sign, private_sign_key)

    print("[7] Data signed using Ed25519")
    print("    Signature:", signature.hex())
    print()

    # ==================================================
    # RECEIVER: verify signature
    # ==================================================
    is_valid = verify(data_to_sign, signature, public_sign_key)

    if not is_valid:
        print("❌ Signature verification FAILED")
        return

    print("[8] Signature verified successfully ✅")
    print()

    # ==================================================
    # RECEIVER: decrypt seed using Merkle–Hellman
    # ==================================================
    recovered_bits = mh_decrypt(encrypted_seed, mh_private_key)
    recovered_seed = bits_to_byte(recovered_bits)

    print("[9] Seed decrypted using Merkle–Hellman")
    print("    Recovered seed byte:", recovered_seed)
    print()

    # ==================================================
    # RECEIVER: derive same Serpent key
    # ==================================================
    recovered_serpent_key = derive_serpent_key(recovered_seed)

    print("[10] Serpent key re-derived from recovered seed")
    print()

    # ==================================================
    # FINAL CHECK
    # ==================================================
    if recovered_serpent_key == serpent_key:
        print("✅ FULL DEMO SUCCESS")
        print("    Serpent key matches on both sides")
    else:
        print("❌ ERROR: Serpent key mismatch")


if __name__ == "__main__":
    main()
