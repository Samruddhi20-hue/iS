# ===== RSA Encryption Program =====
# This program encrypts a message using RSA algorithm
# and demonstrates the use of public and private keys.

import math

# Function to find gcd
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function to find modular inverse (d)
def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return None

# RSA Key Generation
def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1

    # Compute d (private key)
    d = mod_inverse(e, phi)

    return ((e, n), (d, n))  # (public_key, private_key)

# Encryption: C = (M^e) % n
def encrypt(message, public_key):
    e, n = public_key
    encrypted = [(ord(char) ** e) % n for char in message]
    return encrypted

# Decryption: M = (C^d) % n
def decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted = ''.join([chr((char ** d) % n) for char in ciphertext])
    return decrypted


# ========== MAIN PROGRAM ==========
print("===== RSA Encryption Demo =====")
p = int(input("Enter first prime number (p): "))
q = int(input("Enter second prime number (q): "))

public_key, private_key = generate_keys(p, q)

print("\nPublic Key (e, n):", public_key)
print("Private Key (d, n):", private_key)

message = input("\nEnter message to encrypt: ")

ciphertext = encrypt(message, public_key)
print("\nEncrypted Message:", ciphertext)

decrypted_message = decrypt(ciphertext, private_key)
print("Decrypted Message:", decrypted_message)
