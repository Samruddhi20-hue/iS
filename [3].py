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
## 🧠 Overview:
#
# This program shows how RSA encryption works — a famous public-key cryptography algorithm.
# It uses two keys:
#
# Public key → used to encrypt the message
# Private key → used to decrypt the message
#
# The program takes two prime numbers, generates both keys, encrypts a message, and then decrypts it back.
#
# ⚙ Step-by-Step Explanation
#
# 1️⃣ Import and Setup
# import math
#
# Here we import the math module (though not heavily used).
#
# 2️⃣ Function: gcd(a, b)
# def gcd(a, b):
#     while b != 0:
#         a, b = b, a % b
#     return a
#
# 🧩 Meaning:
# This function finds the Greatest Common Divisor (GCD) of two numbers — that’s the largest number that divides both.
#
# It’s used to ensure that two numbers are coprime (i.e., GCD = 1).
# In RSA, the public exponent e must be coprime with φ(n).
#
# 🟢 Example:
# gcd(12, 8) → 4
# gcd(7, 9) → 1 (coprime ✅)
#
# 3️⃣ Function: mod_inverse(e, phi)
# def mod_inverse(e, phi):
#     for d in range(2, phi):
#         if (d * e) % phi == 1:
#             return d
#
# 🧩 Meaning:
# This finds the modular inverse of e with respect to phi.
#
# In RSA, this gives us d, the private key exponent, which satisfies:
# (d × e) mod φ = 1
#
# Basically, d helps reverse the encryption process.
#
# 🟢 Example:
# If e = 7 and φ = 40,
# we find d such that (d × 7) % 40 = 1.
#
# 4️⃣ Function: generate_keys(p, q)
# def generate_keys(p, q):
#     n = p * q
#     phi = (p - 1) * (q - 1)
#
# Step-by-step:
#
# 1️⃣ p and q are prime numbers (input from user).
# 2️⃣ Compute n = p × q → forms part of both keys.
# 3️⃣ Compute φ(n) = (p−1)(q−1) → used to calculate e and d.
#
# Choose e:
# e = 2
# while e < phi:
#     if gcd(e, phi) == 1:
#         break
#     e += 1
#
# It picks the smallest number e such that
# 1 < e < φ and gcd(e, φ) = 1.
# This means e and φ are coprime.
#
# Find d:
# d = mod_inverse(e, phi)
#
# Uses the earlier function to find the private exponent.
#
# Return both keys:
# return ((e, n), (d, n))
#
# ✅ Public key = (e, n)
# ✅ Private key = (d, n)
#
# 5️⃣ Function: encrypt(message, public_key)
# def encrypt(message, public_key):
#     e, n = public_key
#     encrypted = [(ord(char) ** e) % n for char in message]
#     return encrypted
#
# Explanation:
#
# Takes each character of the message.
# Converts it to its ASCII value using ord().
# Applies the RSA formula:
# C = (M^e) mod n
#
# where:
# M = message letter in numeric form,
# C = ciphertext numeric value.
#
# 🟢 Example:
# If M = 65 (A), e = 7, n = 33,
# then C = (65^7) % 33.
#
# The result is stored in a list like [cipher1, cipher2, ...].
#
# 6️⃣ Function: decrypt(ciphertext, private_key)
# def decrypt(ciphertext, private_key):
#     d, n = private_key
#     decrypted = ''.join([chr((char ** d) % n) for char in ciphertext])
#     return decrypted
#
# Explanation:
#
# For each number in the encrypted list:
# M = (C^d) mod n
#
# Convert the result back to a character using chr().
# ✅ This gives back the original message.
#
# 7️⃣ Main Program Execution
#
# print("===== RSA Encryption Demo =====")
# p = int(input("Enter first prime number (p): "))
# q = int(input("Enter second prime number (q): "))
#
# Takes two prime numbers from the user — example: p = 7, q = 17.
#
# Generate keys:
# public_key, private_key = generate_keys(p, q)
#
# It prints both keys:
# Public Key (e, n): (e_value, n_value)
# Private Key (d, n): (d_value, n_value)
#
# Input message and encrypt:
# message = input("Enter message to encrypt: ")
# ciphertext = encrypt(message, public_key)
# print("Encrypted Message:", ciphertext)
#
# You get a list of numbers as the ciphertext.
#
# Decrypt and display:
# decrypted_message = decrypt(ciphertext, private_key)
# print("Decrypted Message:", decrypted_message)
#
# It prints the original message again — proving that RSA works!
#
# 🧩 Example Flow
# Step           Input / Operation          Output
# ------------------------------------------------------
# Input primes   p = 7, q = 17
# Compute        n = 119, φ = 96
# Choose e       e = 5
# Find d         d = 77
# Public Key     (5, 119)
# Private Key    (77, 119)
# Encrypt “HI”   → [72⁵%119, 73⁵%119] → [...encrypted numbers...]
# Decrypt        Using (77, 119) → "HI"
#
# 💬 In Simple Oral Words
#
# “This program shows RSA encryption.
# We first take two prime numbers p and q.
# We multiply them to get n, and calculate φ(n).
# Then we choose e such that it has no common factor with φ.
# Next, we find d — the modular inverse of e.
# The public key (e, n) is used for encryption,
# and the private key (d, n) is used for decryption.
# Encryption converts text into numeric cipher using (M^e) mod n,
# and decryption reverses it using (C^d) mod n.
# Finally, we get back the original message.”