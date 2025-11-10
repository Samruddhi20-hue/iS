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
