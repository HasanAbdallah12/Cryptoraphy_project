from merkle_hellman.keygen import generate_keys
from merkle_hellman.encrypt import encrypt
from merkle_hellman.decrypt import decrypt

# Generate keys
public_key, private_key = generate_keys()

# Example binary message (8 bits)
bits = [1, 0, 1, 1, 0, 0, 1, 0]

print("Original bits:     ", bits)
print("Public key:        ", public_key)

# Encrypt
cipher = encrypt(bits, public_key)
print("Ciphertext:        ", cipher)

# Decrypt
recovered_bits = decrypt(cipher, private_key)
print("Recovered bits:    ", recovered_bits)
 
