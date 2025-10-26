"""
-------------------------------------------------------
CP460 Assignment 1
-------------------------------------------------------
Author:  Sameer Abdullah    
ID:      169065039
Email:   abdu5039@mylaurier.ca
__updated__ = "2025-10-05"
-------------------------------------------------------
"""

import random

# 1. Euclidean Algorithm for GCD
def gcd(a, b):
    """
    -------------------------------------------------------
    Computes and returns the greatest common divisor (GCD)
    of two integers using the Euclidean Algorithm.
    Use: result = gcd(a, b)
    -------------------------------------------------------
    Parameters:
        a - first integer
        b - second integer
    Returns:
        result - greatest common divisor of a and b (int)
    -------------------------------------------------------
    """
    while b != 0:
        a,b = b, a % b
    result = abs(a)
    return result

# 2. Extended Euclidean Algorithm for modular inverse
def mod_inverse(a, n):
    """
    -------------------------------------------------------
    Computes the multiplicative inverse of a modulo n using
    the extended Euclidean algorithm. Returns None if inverse
    does not exist.
    Use: inverse = mod_inverse(a, n)
    -------------------------------------------------------
    Parameters:
        a - integer whose inverse is to be found
        n - modulus (int > 0)
    Returns:
        inverse - multiplicative inverse of a modulo n (int) 
                  or None if it does not exist
    -------------------------------------------------------
    """
    t, new_t = 0,1
    r, new_r = n,a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t- quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        return None # No inverse 
    if t < 0:
        t += n # Inverse is positive

    inverse = t
    return inverse

# 3. Miller-Rabin Primality Test
def is_prime_miller_rabin(n):
    """
    -------------------------------------------------------
    Tests whether n is prime using the Miller-Rabin
    probabilistic algorithm.
    Use: result = is_prime_miller_rabin(n)
    -------------------------------------------------------
    Parameters:
        n - integer to be tested for primality (int > 1)
    Returns:
        result - True if n is probably prime, False otherwise (bool)
    -------------------------------------------------------
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    k = 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
    


# 4. Find Primitive Roots modulo n
def find_primitive_roots(n):
    """
    -------------------------------------------------------
    Finds all primitive roots modulo n, where n is a prime number.
    Use: roots = find_primitive_roots(n)
    -------------------------------------------------------
    Parameters:
        n - prime modulus (int > 1)
    Returns:
        roots - list of integers that are primitive roots modulo n
    -------------------------------------------------------
    """
    if n == 2:
        return [1]

    def prime_factors(num):
        factors = set()
        i = 2
        while i * i <= num:
            while num % i == 0:
                factors.add(i)
                num //= i
            i += 1
        if num > 1:
            factors.add(num)
        return factors

    phi = n - 1
    factors = prime_factors(phi)
    roots = []

    for g in range(2, n):
        is_root = True
        for f in factors:
            if pow(g, phi // f, n) == 1:
                is_root = False
                break
        if is_root:
            roots.append(g)
    return roots


# 5. Discrete Logarithm
def discrete_log(g, y, p):
    """
    -------------------------------------------------------
    Solves for x in g^x ≡ y (mod p) using a discrete log method.
    Use: x = discrete_log(g, y, p)
    -------------------------------------------------------
    Parameters:
        g - base integer (int)
        y - target integer (int)
        p - modulus (int > 1)
    Returns:
        x - discrete log of y to the base g (mod p),
            or None if no solution is found (int or None)
    -------------------------------------------------------
    """
    g %= p
    y %= p
    if y == 1:
        return 0

    def int_sqrt(n):
        x = 0
        while (x + 1) * (x + 1) <= n:
            x += 1
        return x

    m = int_sqrt(p - 1) + 1

    list_t = {}
    val = 1
    for j in range(m):
        if val not in list_t:
            list_t[val] = j
        val = (val * g) % p

    inv_g = pow(g, p - 2, p)
    factor = pow(inv_g, m, p)

    cur = y
    for i in range(m + 1):
        if cur in list_t:
            x = i * m + list_t[cur]
            if pow(g, x, p) == y:
                return x
        cur = (cur * factor) % p

    return None

# 6. Playfair Cipher Encryption
def playfair_encrypt(plaintext, key):
    """
    -------------------------------------------------------
    Encrypts the plaintext using the Playfair cipher with
    the given key.
    Use: ciphertext = playfair_encrypt(plaintext, key)
    -------------------------------------------------------
    Parameters:
        plaintext - message to encrypt (str)
        key - cipher key (str)
    Returns:
        ciphertext - encrypted message (str)
    -------------------------------------------------------
    """
    def clean_up(s):
        s = s.lower()
        s = s.replace('j', 'i')
        return ''.join(ch for ch in s if 'a' <= ch <= 'z')

    def make_square(k):
        k = clean_up(k)
        seen = []
        for ch in k:
            if ch not in seen:
                seen.append(ch)
        for ch in "abcdefghiklmnopqrstuvwxyz":
            if ch not in seen:
                seen.append(ch)
        sq = [seen[i:i+5] for i in range(0, 25, 5)]
        pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
        return sq, pos

    def make_pairs(s):
        s = clean_up(s)
        pairs = []
        i = 0
        while i < len(s):
            a = s[i]
            if i + 1 < len(s):
                b = s[i+1]
                if a == b:
                    pairs.append((a, 'x'))
                    i += 1
                else:
                    pairs.append((a, b))
                    i += 2
            else:
                pairs.append((a, 'x'))
                i += 1
        return pairs

    square, pos = make_square(key)
    out = []

    for a, b in make_pairs(plaintext):
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(square[ra][(ca + 1) % 5])
            out.append(square[rb][(cb + 1) % 5])
        elif ca == cb:
            out.append(square[(ra + 1) % 5][ca])
            out.append(square[(rb + 1) % 5][cb])
        else:
            out.append(square[ra][cb])
            out.append(square[rb][ca])

    return ''.join(out).upper()


# 7. Frequency Analysis 
def frequency_analysis(ciphertext):
    """
    -------------------------------------------------------
    Performs frequency analysis on ciphertext and returns
    all letters with their frequencies as percentages, sorted 
    by frequency (most common first). Ignores spaces, punctuation, and case.
    Use: letter_freq_list = frequency_analysis(ciphertext)
    -------------------------------------------------------
    Parameters:
        ciphertext - encrypted text string (str)
    Returns:
        letter_freq_list - list of tuples (letter, percentage) where
                          letter is uppercase and percentage is rounded 
                          to 1 decimal place, sorted by frequency 
                          from most to least common (list of tuple)
    -------------------------------------------------------
    """
    counts = {}
    total = 0

    for ch in ciphertext.upper():
        if 'A' <= ch <= 'Z':
            counts[ch] = counts.get(ch, 0) + 1
            total += 1

    #counts to percentages
    freq_list = []
    for letter, count in counts.items():
        percent = round((count / total) * 100, 1)
        freq_list.append((letter, percent))

    #(highest first)
    freq_list.sort(key=lambda x: x[1], reverse=True)

    return freq_list 


# ===============
# Partial Tests 
# ===============
def test_gcd():
    print("gcd(48, 18) =", gcd(48, 18), "Expected: 6")

def test_mod_inverse():
    print("mod_inverse(15, 26) =", mod_inverse(15, 26), "Expected: 7")

def test_is_prime_miller_rabin():
    print("is_prime_miller_rabin(17) =", is_prime_miller_rabin(17), "Expected: True")
    print("is_prime_miller_rabin(18) =", is_prime_miller_rabin(18), "Expected: False")

def test_find_primitive_roots():
    print("find_primitive_roots(7) =", find_primitive_roots(7), "Expected: [3,5]")

def test_discrete_log():
    print("discrete_log(2, 8, 11) =", discrete_log(2, 8, 11), "Expected: 3")

def test_playfair_encrypt():
    print("playfair_encrypt('HELLO', 'KEYWORD') =", playfair_encrypt("HELLO", "KEYWORD"), "Expected: GYIZSC")    

def test_frequency_analysis():
    test_text = 'WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ. WKLV LV D VLPSOH PHEOHFN FMESFIWEV WHAFKQLTV.'
    result = frequency_analysis(test_text)
    print("frequency_analysis('WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ. WKLV LV D VLPSOH PHEOHFN FMESFIWEV WHAFKQLTV.') =", result)
    print("Expected: [('H', 9.6), ('V', 8.2), ('F', 6.8), ('L', 6.8), ('W', 6.8), ('E', 5.5), ('K', 5.5), ('R', 5.5), ('O', 4.1), ('P', 4.1), ('S', 4.1), ('A', 2.7), ('D', 2.7), ('I', 2.7), ('M', 2.7), ('N', 2.7), ('Q', 2.7), ('T', 2.7), ('U', 2.7), ('X', 2.7), ('B', 1.4), ('C', 1.4), ('G', 1.4), ('J', 1.4), ('Y', 1.4), ('Z', 1.4)]")
 
    total_letters = sum(1 for char in test_text if char.isalpha())
    print(f"Total letters: {total_letters}")
    print("Breakdown:")
    if result:
        for letter, percentage in result:
            count = round((percentage * total_letters) / 100)
            print(f"  {letter}: {count} occurrences = {percentage}%")

if __name__ == "__main__":
    test_gcd()
    print()
    test_mod_inverse()
    print()
    test_is_prime_miller_rabin()
    print()
    test_find_primitive_roots()
    print()
    test_discrete_log()
    print()
    test_playfair_encrypt()
    print()
    test_frequency_analysis()
