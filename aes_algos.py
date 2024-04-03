import base64
from typing import Literal, Callable

S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

NB = 4
BLOCK_SIZE = 16 # Bytes

AES_128_ROUNDS = 10
AES_192_ROUNDS = 12
AES_256_ROUNDS = 14

AES_128_KEYLEN = 4
AES_192_KEYLEN = 6
AES_256_KEYLEN = 8


def gf_mult_bytes(p1: int, p2: int):
    """Sick multiplication"""

    product = p1 if p2 & 1 == 1 else 0
    temp = p1

    for _ in range(7): # Already did one iteration: you're welcome
        carry = temp & 0x80
        temp <<= 1
        temp &= 0xff # python when bytes
        if carry:
            temp ^= 0x1b # Has x^8, must modulo
        p2 >>= 1
        if (p2 & 1) == 1:
            product ^= temp
    return product

def gf_mult_words(w1: int, w2: int):
    assert 0 <= w1 <= 0xffffffff
    assert 0 <= w2 <= 0xffffffff

    a0, a1, a2, a3 = w1 & 0xff, (w1 & 0xff00) >> 8, (w1 & 0xff0000) >> 16, (w1 & 0xff000000) >> 24
    b0, b1, b2, b3 = w2 & 0xff, (w2 & 0xff00) >> 8, (w2 & 0xff0000) >> 16, (w2 & 0xff000000) >> 24

    product = gf_mult_bytes(a0, b0) ^ gf_mult_bytes(a3, b1) ^ gf_mult_bytes(a2, b2) ^ gf_mult_bytes(a1, b3)
    product |= (gf_mult_bytes(a1, b0) ^ gf_mult_bytes(a0, b1) ^ gf_mult_bytes(a3, b2) ^ gf_mult_bytes(a2, b3)) << 8
    product |= (gf_mult_bytes(a2, b0) ^ gf_mult_bytes(a1, b1) ^ gf_mult_bytes(a0, b2) ^ gf_mult_bytes(a3, b3)) << 16
    product |= (gf_mult_bytes(a3, b0) ^ gf_mult_bytes(a2, b1) ^ gf_mult_bytes(a1, b2) ^ gf_mult_bytes(a0, b3)) << 24
    return product

def rot_word(w1: int):
    assert 0 <= w1 <= 0xffffffff
    return ((w1 << 8) | (w1 >> 24)) & 0xffffffff

def shift_rows(state: bytearray):
    """
    Shifts rows... row-wise
    
    0   1   2   3       0   1   2   3
    4   5   6   7 ==|   5   6   7   4
    8   9  10  11 ==|   10 11   8   9
    12 13  14  15       15 12  13  14

    I could've just hardcoded it but booo
    """

    for i in range(1, NB): # start from the 2nd row
        row = (state[i]) | (state[i + 1*NB] << 8) | (state[i + 2*NB] << 16) | (state[i + 3*NB] << 24)
        wrapping_part = row & ((1 << 8*i) - 1)
        new_row = (row >> 8*i) | (wrapping_part << 32-8*i)
        
        for j in range(4):
            state[i + 4*j] = (new_row & 0xff << 8*j) >> 8*j

def mix_columns(state: bytearray):
    "Multiplies polynomials column wise"

    for i in range(NB):
        column = (state[4*i]) | (state[4*i + 1] << 8) | (state[4*i + 2] << 16) | (state[4*i + 3] << 24)
        new_column = gf_mult_words(column, 0x03010102)
        for j in range(4):
            state[4*i + j] = (new_column & 0xff << 8*j) >> 8*j

def add_round_key(state: bytearray, round_key: list[int]):
    """Add keys column wise"""

    for i in range(NB):
        for j in range(4):
            state[4*i + j] ^= (round_key[i] & 0xff << 24-8*j) >> 24-8*j

def sub_bytes(state: bytearray):
    """Substitute bytes sussy ohio rizz wise"""

    for i in range(NB * 4):
        state[i] = S_BOX[state[i]]

def sub_word(word: int):
    """sub_bytes but a single word"""

    return S_BOX[word & 0xff] | (S_BOX[(word & 0xff00) >> 8] << 8) | (S_BOX[(word & 0xff0000) >> 16] << 16) | (S_BOX[(word & 0xff000000) >> 24]) << 24

def key_expansion(key: bytes, keylen: int, num_rounds: int):
    """Converts itty bitty 128/192/256-bit key to beefy thing"""

    temp = 0
    expanded_key = [0] * (4 * (num_rounds + 1)) # NR rounds + 1 extra thing
    for i in range(keylen):
        expanded_key[i] = (key[4*i] << 24) | (key[4*i + 1] << 16) | (key[4*i + 2] << 8) | (key[4*i + 3]) # Combine to word

    rcon = 0x01000000
    for i in range(keylen, 4 * (num_rounds + 1)):
        temp = expanded_key[i - 1]
        if i % keylen == 0:
            temp = sub_word(rot_word(temp)) ^ rcon
            carry = rcon & 0x80000000

            rcon <<= 1
            if carry: # will overflow, must XOR
                rcon &= 0xffffffff
                rcon ^= 0x1b000000
        elif keylen == 8 and i % 8  == 4: # AES-256 special case
            temp = sub_word(temp)
        expanded_key[i] = expanded_key[i - keylen] ^ temp
    print("E", " ".join(map(hex, expanded_key)))
    print("len", len(expanded_key))
    return expanded_key

def cipher(plain: bytes, round_keys: list[int], num_rounds: int):
    state = bytearray(plain)
    add_round_key(state, round_keys[:NB])

    # First N-1 rounds
    for i in range(num_rounds - 1):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[(i+1)*NB:(i+2)*NB]) # Add round keys following

    # Last round; no mix columns
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[-NB:])
    return bytes(state)

####################################
# INVERSE                          #
####################################

def inv_shift_rows(state: bytearray):
    """
    Shifts rows... row-wise
    
    0   1   2   3       0   1   2   3
    4   5   6   7 ==|   7   4   5   6
    8   9  10  11 ==|   10 11   8   9
    12 13  14  15       13 14  15  12

    I could've just hardcoded it but booo
    """

    for i in range(1, NB): # start from the 2nd row
        row = (state[i]) | (state[i + 1*NB] << 8) | (state[i + 2*NB] << 16) | (state[i + 3*NB] << 24)
        part_to_move = row & ((1 << 32-8*i) - 1)
        wrapping_part = row >> 32-8*i
        new_row = (wrapping_part) | (part_to_move << 8*i)
        
        for j in range(4):
            state[i + 4*j] = (new_row & 0xff << 8*j) >> 8*j

def inv_mix_columns(state: bytearray):
    "Multiplies polynomials column wise"

    for i in range(NB):
        column = (state[4*i]) | (state[4*i + 1] << 8) | (state[4*i + 2] << 16) | (state[4*i + 3] << 24)
        new_column = gf_mult_words(column, 0x0b0d090e)
        for j in range(4):
            state[4*i + j] = (new_column & 0xff << 8*j) >> 8*j

def inv_sub_bytes(state: bytearray):
    """Substitute bytes sussy ohio rizz wise"""

    for i in range(NB * 4):
        state[i] = INV_S_BOX[state[i]]

def inv_cipher(cipher: bytes, round_keys: list[int], num_rounds: int):
    state = bytearray(cipher)
    add_round_key(state, round_keys[NB:])

    for i in range(num_rounds - 1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[-(i+2)*NB:-(i+1)*NB]) # Backtrack the key words
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[:NB])

    return bytes(state)

####################################
# API STUFF                        #
####################################

def encrypt_ecb_factory(algo: Literal[128, 192, 256]) -> Callable[[bytes, bytes], bytes]:
    if algo == 128:
        keylen = AES_128_KEYLEN
        rounds = AES_128_ROUNDS
    elif algo == 192:
        keylen = AES_192_KEYLEN
        rounds = AES_192_ROUNDS
    elif algo == 256:
        keylen = AES_256_KEYLEN
        rounds = AES_256_ROUNDS
    else:
        raise ValueError("Unknown algorithm (must be 128, 192, or 256)")

    def inner(plaintext: bytes, key: bytes) -> bytes:
        expanded_key = key_expansion(key, keylen, rounds)

        i = -1 # Teehee; counteract the (i+1)*BLOCK_SIZE
        ciphertext = bytearray()
        for i in range(len(plaintext) // BLOCK_SIZE):
            block = plaintext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            ciphertext.extend(cipher(block, expanded_key, rounds))
        if len(plaintext) % BLOCK_SIZE != 0:
            final_block = plaintext[(i+1)*BLOCK_SIZE:].ljust(BLOCK_SIZE, b"\x00") # Add padding to remainder of block (ooh spicy loop variable usage)
            ciphertext.extend(cipher(final_block, expanded_key, rounds))

        return bytes(ciphertext)
    return inner

def decrypt_ecb_factory(algo: Literal[128, 192, 256]) -> Callable[[bytes, bytes], bytes]:
    if algo == 128:
        keylen = AES_128_KEYLEN
        rounds = AES_128_ROUNDS
    elif algo == 192:
        keylen = AES_192_KEYLEN
        rounds = AES_192_ROUNDS
    elif algo == 256:
        keylen = AES_256_KEYLEN
        rounds = AES_256_ROUNDS
    else:
        raise ValueError("Unknown algorithm (must be 128, 192, or 256)")

    def inner(ciphertext: bytes, key: bytes) -> bytes:
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Invalid ciphertext (not a multiple of 16 bytes!)")

        expanded_key = key_expansion(key, keylen, rounds)
        plaintext = bytearray()
        for i in range(len(ciphertext) // BLOCK_SIZE):
            block = ciphertext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            plaintext.extend(inv_cipher(block, expanded_key, rounds))
        
        return bytes(plaintext)
    return inner

encrypt_128_ecb = encrypt_ecb_factory(128)
decrypt_128_ecb = decrypt_ecb_factory(128)

encrypt_192_ecb = encrypt_ecb_factory(192)
decrypt_192_ecb = decrypt_ecb_factory(192)

encrypt_256_ecb = encrypt_ecb_factory(256)
decrypt_256_ecb = decrypt_ecb_factory(256)

def decrypt_128_ecb_base64(ciphertext: bytes, key: bytes) -> bytes:
    actual = base64.b64decode(ciphertext)
    return decrypt_128_ecb(actual, key)

def decrypt_192_ecb_base64(ciphertext: bytes, key: bytes) -> bytes:
    actual = base64.b64decode(ciphertext)
    return decrypt_192_ecb(actual, key)

def decrypt_256_ecb_base64(ciphertext: bytes, key: bytes) -> bytes:
    actual = base64.b64decode(ciphertext)
    return decrypt_256_ecb(actual, key)

if __name__ == "__main__":
    ECB_FUNCTIONS = {
        128: (encrypt_128_ecb, decrypt_128_ecb_base64),
        192: (encrypt_192_ecb, decrypt_192_ecb_base64),
        256: (encrypt_256_ecb, decrypt_256_ecb_base64)
    }

    print("Hey")
    algo = input("Enter desired AES key size (128/192/256): ")
    if not algo.isdigit() and algo not in (128, 192, 256):
        print("You suck; assumming AES-256")
        algo = 256
    algo = int(algo)

    encrypt_ecb, decrypt_ecb = ECB_FUNCTIONS[algo]

    keyhex = input(f"Enter AES-{algo} key (Hex, no spaces): ")
    if len(keyhex) != algo // 4: # 128/4 = 32, 192/4 = 48, 256/4 = 64
        print("You suck: Assumming key with all 0s")
        keyhex = "00" * (algo // 8)

    key = bytes.fromhex(keyhex)
    print("=========")
    print(f"Key: {' '.join(hex(b)[2:] for b in key)}")
    print(f"Key: {key.hex()}")
    print("=========")

    enc_or_dec = input("Wanna encrypt or decrypt? (e/d) ").lower()
    if enc_or_dec == "e":
        plaintext = input(f"Enter your text; it will be encrypted with AES-{algo} in ECB mode. ")

        ciphertext = encrypt_ecb(plaintext.encode(), key)
        print("=========")
        print(f"Cipher: {ciphertext}")
        print("=====")
        print(f"Cipherhex: {ciphertext.hex()}")
        print("=====")
        print(f"Cipherbase: {base64.b64encode(ciphertext)}")
        print("=========")
    elif enc_or_dec == "d":
        ciphertext = input(f"Enter your base64 ciphertext; it will be decrypted with AES-{algo} in ECB mode. ")
        plaintext = decrypt_ecb(ciphertext.encode(), key)
        print("=========")
        print(f"Plaintext:\n{plaintext}")
        print("=========")
