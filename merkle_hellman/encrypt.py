def encrypt(bits, public_key):
    # Check that both lists have the same length
    if len(bits) != len(public_key):
        print("Error: bits and public key must be the same length")
        return None

    # Start with no sum
    ciphertext = 0

    # Go through the lists one index at a time
    for i in range(len(bits)):
        # If the bit is 1, add the matching public key value
        if bits[i] == 1:
            ciphertext = ciphertext + public_key[i]

    # Return the final sum
    return ciphertext
