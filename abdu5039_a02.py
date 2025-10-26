"""
-------------------------------------------------------
CP460 Assignment 2
-------------------------------------------------------
Author:  Sameer Abdullah
ID:      169065039
Email:   abdu5039@mylaurier.ca
__updated__ = "2025-10-26"
-------------------------------------------------------
"""

import random

AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# -------------------------------------------------------
# 1. Finite Field Addition in GF(2^8)
# -------------------------------------------------------

def gf_add(a, b):
    """
    -------------------------------------------------------
    Performs addition in GF(2^8).
    In GF(2^8), addition is bitwise XOR.
    Use: result = gf_add(a, b)
    -------------------------------------------------------
    Parameters:
        a - first byte value (int)
        b - second byte value (int)
    Returns:
        result - sum of a and b in GF(2^8) (int)
    -------------------------------------------------------
    """
    return a ^ b

# -------------------------------------------------------
# 2. Finite Field Multiplication in GF(2^8)
# -------------------------------------------------------

def gf_mult(a, b):
    """
    -------------------------------------------------------
    Performs multiplication in GF(2^8) using the AES irreducible polynomial
    x^8 + x^4 + x^3 + x + 1 (0x11B).
    Use: result = gf_mult(a, b)
    -------------------------------------------------------
    Parameters:
        a - first byte value (int)
        b - second byte value (int)
    Returns:
        result - product of a and b in GF(2^8) (int)
    -------------------------------------------------------
    """
    result = 0

    for i in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a <<= 1
        if high_bit:
            a^= 0x1B
        a &= 0xFF
        b >>= 1
    return result


# -------------------------------------------------------
# 3. Linear Congruential Generator (LCG)
# -------------------------------------------------------

def lcg(seed, a, c, m, n):
    """
    -------------------------------------------------------
    Generates a sequence of pseudo-random numbers using 
    the Linear Congruential Generator algorithm.
    Use: sequence = lcg(seed, a, c, m, n)
    -------------------------------------------------------
    Parameters:
        seed - initial value (int)
        a - multiplier (int)
        c - increment (int)
        m - modulus (int)
        n - number of values to generate (int)
    Returns:
        sequence - list of n pseudo-random integers (list of int)
    -------------------------------------------------------
    """
    values = []
    x = seed
    for i in range(n):
        x = (a * x + c) % m
        values.append(x)
    return values

# -------------------------------------------------------
# 4. XOR Stream Cipher Encryption and Decryption
# -------------------------------------------------------

def xor_stream_cipher(message_bytes, key_stream):
    """
    -------------------------------------------------------
    Encrypts or decrypts a message using XOR with the key stream.
    (XORing twice with the same key stream restores the original.)
    Use: cipher_bytes = xor_stream_cipher(message_bytes, key_stream)
    -------------------------------------------------------
    Parameters:
        message_bytes - list of message bytes (list of int)
        key_stream - list of key stream bytes (list of int)
    Returns:
        cipher_bytes - encrypted or decrypted bytes (list of int)
    -------------------------------------------------------
    """
    if len(message_bytes) != len(key_stream):
        raise ValueError("message_bytes and key_stream must be the same length")
    return [(m ^ k) & 0xFF for m, k in zip(message_bytes, key_stream)]

# -------------------------------------------------------
# 5. Stream Cipher Using a PRNG Key Stream
# -------------------------------------------------------

def prng_stream_cipher(message, seed, a, c, m):
    """
    -------------------------------------------------------
    Encrypts a plaintext string using a pseudo-random key stream
    generated by a linear congruential generator.
    The same parameters and seed decrypt the message.
    Use: cipher = prng_stream_cipher(message, seed, a, c, m)
    -------------------------------------------------------
    Parameters:
        message - plaintext or ciphertext string (str)
        seed - initial seed for PRNG (int)
        a - multiplier (int)
        c - increment (int)
        m - modulus (int)
    Returns:
        result - encrypted or decrypted string (str)
    -------------------------------------------------------
    """
    msg_codes = [ord(ch) for ch in message]

    ks = [x % 256 for x in lcg(seed, a, c, m, len(msg_codes))]

    out_codes = [(mc ^ k) & 0xFF for mc, k in zip(msg_codes, ks)]

    result = ''.join(chr(v) for v in out_codes)
    return result

# -----------------------------
# 6. Mini AES Encryption Round 
# -----------------------------

def mini_aes_round(state):
    """
    -------------------------------------------------------
    Performs a simplified AES encryption round on a 4x4 state matrix.
    The round consists of the following three transformations:
      1. SubBytes – substitute each byte using the AES S-box.
      2. ShiftRows – cyclically shift each row by its index.
      3. MixColumns – mix each column using finite field arithmetic.
    Use: new_state = mini_aes_round(state)
    -------------------------------------------------------
    Parameters:
        state - 4x4 AES state matrix (list of lists of int)
    Returns:
        new_state - transformed 4x4 state matrix after one AES round (list of lists of int)
    -------------------------------------------------------
    """
    sub_state = [[AES_SBOX[byte] for byte in row] for row in state]

    shifted_state = []
    for i, row in enumerate(sub_state):
        shifted_state.append(row[i:] + row[:i])  

    new_state = [[0]*4 for _ in range(4)]
    for j in range(4): 
        s0, s1, s2, s3 = shifted_state[0][j], shifted_state[1][j], shifted_state[2][j], shifted_state[3][j]
        new_state[0][j] = (gf_mult(s0, 2) ^ gf_mult(s1, 3) ^ s2 ^ s3) & 0xFF
        new_state[1][j] = (s0 ^ gf_mult(s1, 2) ^ gf_mult(s2, 3) ^ s3) & 0xFF
        new_state[2][j] = (s0 ^ s1 ^ gf_mult(s2, 2) ^ gf_mult(s3, 3)) & 0xFF
        new_state[3][j] = (gf_mult(s0, 3) ^ s1 ^ s2 ^ gf_mult(s3, 2)) & 0xFF

    return new_state

# =================
# Partial Tests
# =================

def test_gf_add():
    print("gf_add(0x57, 0x83) =", hex(gf_add(0x57, 0x83)), "Expected: 0xd4")

def test_gf_mult():
    print("gf_mult(0x57, 0x83) =", hex(gf_mult(0x57, 0x83)), "Expected: 0xc1")

def test_lcg():
    seq = lcg(seed=12345, a=1664525, c=1013904223, m=2**32, n=5)
    print("lcg(seed=12345, n=5) =", seq)
    print("Expected: [87628868, 71072467, 2332836374, 2726892157, 3908547000]")

def test_xor_stream_cipher():
    plaintext = [ord(c) for c in "HELLO"]
    key_stream = [0x1, 0x2, 0x3, 0x4, 0x5]
    cipher = xor_stream_cipher(plaintext, key_stream)
    decrypted = xor_stream_cipher(cipher, key_stream)
    print("xor_stream_cipher encryption:", cipher)
    print("xor_stream_cipher decryption:", decrypted)
    print("Expected decryption:", plaintext)

def test_prng_stream_cipher():
    message = "HELLO"
    encrypted = prng_stream_cipher(message, seed=123, a=1664525, c=1013904223, m=2**32)
    decrypted = prng_stream_cipher(encrypted, seed=123, a=1664525, c=1013904223, m=2**32)
    print("prng_stream_cipher encrypted:", encrypted)
    print("prng_stream_cipher decrypted:", decrypted)
    print("Expected decrypted:", message)

def test_mini_aes_round():
    state = [
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34]
    ]
    print("Original state:")
    for row in state:
        print([hex(x) for x in row])
    
    transformed = mini_aes_round(state)
    
    print("\nTransformed state:")
    for row in transformed:
        print([hex(x) for x in row])
    
    print("\nExpected:")
    expected = [
        [0xC1, 0xC6, 0x3F, 0xC9],
        [0x96, 0xC7, 0x73, 0xE3],
        [0x39, 0xCF, 0x3E, 0xBD],
        [0xAD, 0xCA, 0x30, 0x52]
    ]
    for row in expected:
        print([hex(x) for x in row])
    
if __name__ == "__main__":
    print("Testing GF(2^8) addition:")
    test_gf_add()
    print("\nTesting GF(2^8) multiplication:")
    test_gf_mult()
    print("\nTesting LCG PRNG:")
    test_lcg()
    print("\nTesting XOR Stream Cipher:")
    test_xor_stream_cipher()
    print("\nTesting PRNG Stream Cipher:")
    test_prng_stream_cipher()
    print("\nTesting Mini AES Round:")
    test_mini_aes_round()
