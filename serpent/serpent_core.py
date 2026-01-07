# serpent/serpent_core.py
# --------------------------------------------------
# Educational Serpent-style block cipher
# - 128-bit blocks (16 bytes)
# - 32 rounds 
# --------------------------------------------------


def xor_bytes(block1, block2):
    result = bytearray()

    for i in range(len(block1)):
        result.append(block1[i] ^ block2[i])

    return bytes(result)


def pad_data(data):
    block_size = 16
    padding_needed = block_size - (len(data) % block_size)

    padding = bytes([padding_needed]) * padding_needed
    return data + padding


def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]


def substitute_block(block):
    # Simple non-linear substitution (educational)
    substituted = bytearray()

    for i in range(len(block)):
        substituted.append((block[i] + 1) % 256)

    return bytes(substituted)


def inverse_substitute_block(block):
    restored = bytearray()

    for i in range(len(block)):
        restored.append((block[i] - 1) % 256)

    return bytes(restored)


def encrypt_block(block, key):
    rounds = 32  # ✅ Real Serpent uses 32 rounds
    state = block

    for r in range(rounds):
        state = xor_bytes(state, key)
        state = substitute_block(state)

    return state


def decrypt_block(block, key):
    rounds = 32  # ✅ Real Serpent uses 32 rounds
    state = block

    for r in range(rounds):
        state = inverse_substitute_block(state)
        state = xor_bytes(state, key)

    return state
