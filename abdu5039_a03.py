"""
-------------------------------------------------------
CP460 Assignment 3
-------------------------------------------------------
Author:  Sameer Abdullah
ID:      169065039
Email:   abdu5039@mylaurier.ca
__updated__ = "2025-11-13"
-------------------------------------------------------
"""

import random

# -------------------------------------------------------
# 1. Modular Multiplicative Inverse
# -------------------------------------------------------

def mod_inverse(a, m):
    """
    -------------------------------------------------------
    Computes the modular multiplicative inverse of a modulo m.
    Uses the Extended Euclidean Algorithm from Assignment 1.
    Use: inverse = mod_inverse(a, m)
    -------------------------------------------------------
    Parameters:
        a - integer to find inverse of (int)
        m - modulus (int)
    Returns:
        inverse - modular inverse of a mod m, or None if it doesn't exist (int or None)
    -------------------------------------------------------
    """
    a = a % m
    r0, r1 = m, a
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        return None
    return t0 % m

# -------------------------------------------------------
# 2. RSA Key Generation
# -------------------------------------------------------

def rsa_keygen(p, q, e=65537):
    """
    -------------------------------------------------------
    Generates RSA public and private keys given two primes p and q.
    Use: public_key, private_key = rsa_keygen(p, q, e)
    -------------------------------------------------------
    Parameters:
        p - first prime number (int)
        q - second prime number (int)
        e - public exponent (int, default: 65537)
    Returns:
        public_key - tuple (n, e) (tuple of int)
        private_key - tuple (n, d) (tuple of int)
    -------------------------------------------------------
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    if d is None:
        raise ValueError("e has no modular inverse modulo φ(n).")
    return (n, e), (n, d)

# -------------------------------------------------------
# 3. RSA Encryption
# -------------------------------------------------------

def rsa_encrypt(plaintext, public_key):
    """
    -------------------------------------------------------
    Encrypts a message using RSA.
    Use: ciphertext = rsa_encrypt(plaintext, public_key)
    -------------------------------------------------------
    Parameters:
        plaintext - message to encrypt, must be < n (int)
        public_key - RSA public key (n, e) (tuple of int)
    Returns:
        ciphertext - encrypted message (int)
    -------------------------------------------------------
    """
    n, e = public_key
    return pow(plaintext, e, n)

# -------------------------------------------------------
# 4. RSA Decryption
# -------------------------------------------------------

def rsa_decrypt(ciphertext, private_key):
    """
    -------------------------------------------------------
    Decrypts a ciphertext using RSA.
    Use: plaintext = rsa_decrypt(ciphertext, private_key)
    -------------------------------------------------------
    Parameters:
        ciphertext - encrypted message (int)
        private_key - RSA private key (n, d) (tuple of int)
    Returns:
        plaintext - decrypted message (int)
    -------------------------------------------------------
    """
    n, d = private_key
    return pow(ciphertext, d, n)

# -------------------------------------------------------
# 5. Simple Hash Function
# -------------------------------------------------------

def simple_hash(message, table_size=256):
    """
    -------------------------------------------------------
    Implements a simple hash function using polynomial rolling hash.
    Hash formula: h(s) = (s[0]*p^(n-1) + s[1]*p^(n-2) + ... + s[n-1]) mod table_size
    where p = 31 (a small prime).
    Use: hash_value = simple_hash(message, table_size)
    -------------------------------------------------------
    Parameters:
        message - input string to hash (str)
        table_size - size of hash table (modulus) (int, default: 256)
    Returns:
        hash_value - hash value in range [0, table_size-1] (int)
    -------------------------------------------------------
    """
    p = 31
    h = 0
    for ch in message:
        h = (h * p + ord(ch)) % table_size
    return h

# -------------------------------------------------------
# 6. HMAC (Hash-based Message Authentication Code)
# -------------------------------------------------------

def simple_hmac(key, message, hash_func=simple_hash):
    """
    -------------------------------------------------------
    Computes a simplified HMAC using the provided hash function.
    Simplified HMAC: HMAC(K, m) = H(K || H(K || m))
    where || denotes concatenation.
    Use: mac = simple_hmac(key, message, hash_func)
    -------------------------------------------------------
    Parameters:
        key - secret key (str)
        message - message to authenticate (str)
        hash_func - hash function to use (function, default: simple_hash)
    Returns:
        mac - HMAC value (int)
    -------------------------------------------------------
    """
    inner = hash_func(key + message)
    return hash_func(key + str(inner))

# -------------------------------------------------------
# 7. RSA Digital Signature (Sign)
# -------------------------------------------------------

def rsa_sign(message_hash, private_key):
    """
    -------------------------------------------------------
    Creates an RSA digital signature by signing a message hash.
    Use: signature = rsa_sign(message_hash, private_key)
    -------------------------------------------------------
    Parameters:
        message_hash - hash of the message to sign (int)
        private_key - RSA private key (n, d) (tuple of int)
    Returns:
        signature - digital signature (int)
    -------------------------------------------------------
    """
    n, d = private_key
    return pow(message_hash, d, n)

# -------------------------------------------------------
# 8. RSA Digital Signature (Verify)
# -------------------------------------------------------

def rsa_verify(message_hash, signature, public_key):
    """
    -------------------------------------------------------
    Verifies an RSA digital signature.
    Use: is_valid = rsa_verify(message_hash, signature, public_key)
    -------------------------------------------------------
    Parameters:
        message_hash - hash of the original message (int)
        signature - digital signature to verify (int)
        public_key - RSA public key (n, e) (tuple of int)
    Returns:
        is_valid - True if signature is valid, False otherwise (bool)
    -------------------------------------------------------
    """
    n, e = public_key
    recovered_hash = pow(signature, e, n)
    return recovered_hash == message_hash

# =================
# Partial Tests
# =================

def test_mod_inverse():
    print("Testing Modular Inverse:")
    inv = mod_inverse(3, 11)
    print(f"mod_inverse(3, 11) = {inv}")
    print(f"Verification: (3 * {inv}) mod 11 = {(3 * inv) % 11}")
    print(f"Expected: 4")

def test_rsa_keygen():
    print("\nTesting RSA Key Generation:")
    p, q = 61, 53
    public_key, private_key = rsa_keygen(p, q)
    print(f"p={p}, q={q}")
    print(f"Public key (n, e): {public_key}")
    print(f"Private key (n, d): {private_key}")
    print(f"Expected: n={p*q}=3233")

def test_rsa_encrypt_decrypt():
    print("\nTesting RSA Encryption/Decryption:")
    p, q = 61, 53
    public_key, private_key = rsa_keygen(p, q)
    plaintext = 123
    ciphertext = rsa_encrypt(plaintext, public_key)
    decrypted = rsa_decrypt(ciphertext, private_key)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    print(f"Expected: Decrypted should equal {plaintext}")

def test_simple_hash():
    print("\nTesting Simple Hash Function:")
    h1 = simple_hash("hello")
    h2 = simple_hash("hello")
    h3 = simple_hash("world")
    print(f"simple_hash('hello') = {h1}")
    print(f"simple_hash('hello') = {h2} (should be same)")
    print(f"simple_hash('world') = {h3} (should be different)")
    print(f"Expected: h1 == h2, h1 != h3")

def test_simple_hmac():
    print("\nTesting Simple HMAC:")
    key = "secret"
    message = "hello"
    mac1 = simple_hmac(key, message)
    mac2 = simple_hmac(key, message)
    mac3 = simple_hmac("wrong_key", message)
    print(f"simple_hmac('secret', 'hello') = {mac1}")
    print(f"simple_hmac('secret', 'hello') = {mac2} (should be same)")
    print(f"simple_hmac('wrong_key', 'hello') = {mac3} (should be different)")
    print(f"Expected: mac1 == mac2, mac1 != mac3")

def test_rsa_signature():
    print("\nTesting RSA Digital Signature:")
    p, q = 61, 53
    public_key, private_key = rsa_keygen(p, q)
    
    message = "Important message"
    message_hash = simple_hash(message, table_size=1000)
    
    signature = rsa_sign(message_hash, private_key)
    is_valid = rsa_verify(message_hash, signature, public_key)
    
    # Try with tampered message
    tampered_hash = simple_hash("Tampered message", table_size=1000)
    is_valid_tampered = rsa_verify(tampered_hash, signature, public_key)
    
    print(f"Message: '{message}'")
    print(f"Message hash: {message_hash}")
    print(f"Signature: {signature}")
    print(f"Signature valid: {is_valid}")
    print(f"Tampered message valid: {is_valid_tampered}")
    print(f"Expected: Original valid=True, Tampered valid=False")

if __name__ == "__main__":
    test_mod_inverse()
    test_rsa_keygen()
    test_rsa_encrypt_decrypt()
    test_simple_hash()
    test_simple_hmac()
    test_rsa_signature()