#!/usr/bin/env python3
"""
AES Encrypt / Decrypt (CBC) with password-derived key (PBKDF2).
Stores: base64(salt || iv || ciphertext)
"""

import base64
import getpass
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Constants
SALT_SIZE = 16      # bytes
IV_SIZE = 16        # bytes (AES block size)
KEY_SIZE = 32       # 256-bit key
PBKDF2_ITERS = 200_000  # iterations for key derivation (adjust for your CPU/security needs)

# PKCS7 padding
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Input data is empty, cannot unpad.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    # PBKDF2 with SHA-256
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=iterations, hmac_hash_module=SHA256)

def encrypt(plaintext: str, password: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    payload = salt + iv + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt(b64_payload: str, password: str) -> str:
    try:
        payload = base64.b64decode(b64_payload)
    except Exception as e:
        raise ValueError("Input is not valid Base64.") from e

    if len(payload) < SALT_SIZE + IV_SIZE + 1:
        raise ValueError("Payload too short. Not a valid encrypted message.")

    salt = payload[:SALT_SIZE]
    iv = payload[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = payload[SALT_SIZE + IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext_bytes = pkcs7_unpad(padded)
    return plaintext_bytes.decode('utf-8')

def main():
    print("AES-256 (CBC) encrypt/decrypt with password-derived key (PBKDF2).")
    print("Choose operation: [E]ncrypt or [D]ecrypt")
    choice = input("Enter E or D: ").strip().lower()

    if choice == 'e' or choice == 'encrypt':
        text = input("Enter plaintext to encrypt: ")
        # For password input use getpass to avoid echo
        password = getpass.getpass("Enter password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match. Aborting.")
            sys.exit(1)
        encrypted = encrypt(text, password)
        print("\nEncrypted (Base64):\n")
        print(encrypted)
        print("\nNote: share this full Base64 string (it contains salt + iv + ciphertext).")
    elif choice == 'd' or choice == 'decrypt':
        b64 = input("Enter Base64 payload to decrypt: ").strip()
        password = getpass.getpass("Enter password: ")
        try:
            plaintext = decrypt(b64, password)
            print("\nDecrypted plaintext:\n")
            print(plaintext)
        except Exception as e:
            print(f"Decryption failed: {e}")
            sys.exit(2)
    else:
        print("Invalid choice. Use 'E' to encrypt or 'D' to decrypt.")
        sys.exit(1)

if __name__ == "__main__":
    main()
## 🧠 Main Idea (in one line)
# This Python program encrypts and decrypts text using AES (Advanced #Encryption Standard) with a password-based key. AES (Advanced Encryption #Standard) is a symmetric key encryption algorithm used to protect data.
#It encrypts data in fixed blocks of 128 bits using 128, 192, or 256-bit keys.
#The same key is used for both encryption and decryption, making it fast and #secure.
# That means:
# → You enter a message and a password → it locks (encrypts) the message.
# → Using the same password → it unlocks (decrypts) it again.
#
# 🧩 Step-by-Step Explanation
#
# 1️⃣ Importing Libraries
# import base64, getpass, sys
# from Crypto.Cipher import AES
# from Crypto.Protocol.KDF import PBKDF2
# from Crypto.Hash import SHA256
# from Crypto.Random import get_random_bytes
#
# AES – the encryption algorithm.
# PBKDF2 + SHA256 – converts your password into a strong secret key.
# base64 – converts binary data into text form so it can be easily stored or shared.
# getpass – hides your password when you type it.
# get_random_bytes – generates random salt and IV (used for security).
#
# 2️⃣ Constants
# SALT_SIZE = 16
# IV_SIZE = 16
# KEY_SIZE = 32
# PBKDF2_ITERS = 200_000
#
# Salt (16 bytes): Random data mixed with password to make every key unique.
# IV (16 bytes): Random number used for AES CBC mode.
# KEY_SIZE = 32 bytes: Means 256-bit key (strongest AES).
# Iterations = 200,000: Number of rounds PBKDF2 runs to make key generation slower (for better security).
#
# 3️⃣ Padding (PKCS7)
# AES can only encrypt data in blocks of 16 bytes, so:
# def pkcs7_pad(data): ...
# def pkcs7_unpad(data): ...
#
# pkcs7_pad – adds extra bytes if data isn’t a multiple of 16.
# pkcs7_unpad – removes that extra padding when decrypting.
#
# 🟢 Example:
# If text = "HELLO" → 5 letters → adds padding to make 16 bytes total.
#
# 4️⃣ Key Derivation
# def derive_key(password, salt):
#     return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
#
# This function turns your password into a strong encryption key using:
# → PBKDF2 algorithm  
# → SHA-256 hashing  
# → The random salt  
#
# ✅ So even if two people use the same password, they’ll get different keys due to different salts.
#
# 5️⃣ Encrypt Function
# def encrypt(plaintext, password):
#
# Steps:
# 1. Create random salt and IV.
# 2. Derive a key using the password + salt.
# 3. Pad the plaintext.
# 4. Encrypt using AES in CBC mode.
# 5. Combine salt + IV + ciphertext → convert to Base64 (so it looks like text).
# ✅ This Base64 string can be copied and shared safely.
#
# 6️⃣ Decrypt Function
# def decrypt(b64_payload, password):
#
# Steps:
# 1. Decode Base64 → get back salt, IV, ciphertext.
# 2. Derive the same key using the same password and salt.
# 3. Decrypt using AES.
# 4. Remove padding and convert bytes → text again.
# ⚠ If the password is wrong → decryption fails.
#
# 7️⃣ Main Function
# def main():
#
# Asks user whether to Encrypt or Decrypt.
# Takes input text and password.
# Uses getpass so password isn’t shown.
# If encrypting → shows Base64 ciphertext.
# If decrypting → prints original message.
#
# 8️⃣ Program Execution
# if _name_ == "_main_":
#     main()
#
# This line ensures that the program runs only when directly executed (not imported as a module).
#
# 🔐 In Simple Viva Words
# “This program uses AES encryption in CBC mode.
# It first converts the user’s password into a secret key using PBKDF2 and SHA-256.
# Then it encrypts the message and stores salt, IV, and ciphertext together in Base64 format.
# During decryption, the same password regenerates the key to unlock the original message.”
#
# 🧾 Short Summary Table
# Term        Meaning
# AES         Advanced Encryption Standard
# CBC         Cipher Block Chaining mode
# PBKDF2      Converts password → key
# Salt        Random data for uniqueness
# IV          Initialization Vector
# Base64      Converts binary → text
# Padding     Adjusts data to block size