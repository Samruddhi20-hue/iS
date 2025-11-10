# ======== CIPHER PROGRAM ======== #
# Supports: Playfair, Vigenère, Simple Columnar, and Rail Fence Cipher
# Handles odd-length text and numeric keys automatically
# Includes a looping menu for multiple operations

import math

# ------------------ Helper: Convert numeric/mixed keys to alphabets ------------------ #
def clean_key(key):
    cleaned = ""
    for ch in key:
        if ch.isalpha():
            cleaned += ch.upper()
        elif ch.isdigit():
            # Convert numbers to letters (1→A, 2→B, etc.)
            cleaned += chr((int(ch) - 1) % 26 + 65)
    if not cleaned:
        cleaned = "KEY"  # fallback if empty
    return cleaned

# ------------------ PLAYFAIR CIPHER ------------------ #
def generate_playfair_matrix(key):
    key = clean_key(key).replace("J", "I")
    matrix = []
    used = set()

    for ch in key:
        if ch not in used and ch.isalpha():
            used.add(ch)
            matrix.append(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            used.add(ch)
            matrix.append(ch)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, ch):
    for i, row in enumerate(matrix):
        if ch in row:
            return i, row.index(ch)
    return None

def playfair_encrypt(text, key):
    text = text.upper().replace(" ", "").replace("J", "I")
    if len(text) % 2 != 0:
        text += "X"

    matrix = generate_playfair_matrix(key)
    cipher = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            cipher += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            cipher += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            cipher += matrix[row1][col2] + matrix[row2][col1]
    return cipher

def playfair_decrypt(cipher, key):
    cipher = cipher.upper().replace(" ", "")
    if len(cipher) % 2 != 0:
        cipher += "X"
    matrix = generate_playfair_matrix(key)
    text = ""

    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i+1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            text += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            text += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            text += matrix[row1][col2] + matrix[row2][col1]
    return text


# ------------------ VIGENERE CIPHER ------------------ #
def generate_vigenere_key(text, key):
    key = clean_key(key)
    key = list(key)
    if len(text) == len(key):
        return "".join(key)
    else:
        for i in range(len(text) - len(key)):
            key.append(key[i % len(key)])
    return "".join(key)

def vigenere_encrypt(text, key):
    text = text.upper().replace(" ", "")
    cipher = ""
    key = generate_vigenere_key(text, key)
    for i in range(len(text)):
        if text[i].isalpha():
            x = (ord(text[i]) + ord(key[i])) % 26
            cipher += chr(x + 65)
        else:
            cipher += text[i]
    return cipher

def vigenere_decrypt(cipher, key):
    cipher = cipher.upper().replace(" ", "")
    text = ""
    key = generate_vigenere_key(cipher, key)
    for i in range(len(cipher)):
        if cipher[i].isalpha():
            x = (ord(cipher[i]) - ord(key[i]) + 26) % 26
            text += chr(x + 65)
        else:
            text += cipher[i]
    return text


# ------------------ SIMPLE COLUMNAR CIPHER ------------------ #
def columnar_encrypt(text, key):
    text = text.replace(" ", "").upper()
    key = clean_key(key)
    key_order = sorted(list(key))
    col = len(key)
    row = math.ceil(len(text) / col)
    matrix = [['' for _ in range(col)] for _ in range(row)]
    
    idx = 0
    for i in range(row):
        for j in range(col):
            if idx < len(text):
                matrix[i][j] = text[idx]
                idx += 1

    cipher = ""
    for k in key_order:
        col_idx = key.index(k)
        for i in range(row):
            if matrix[i][col_idx] != '':
                cipher += matrix[i][col_idx]
    return cipher

def columnar_decrypt(cipher, key):
    cipher = cipher.replace(" ", "").upper()
    key = clean_key(key)
    key_order = sorted(list(key))
    col = len(key)
    row = math.ceil(len(cipher) / col)
    matrix = [['' for _ in range(col)] for _ in range(row)]

    idx = 0
    for k in key_order:
        col_idx = key.index(k)
        for i in range(row):
            if idx < len(cipher):
                matrix[i][col_idx] = cipher[idx]
                idx += 1

    text = ""
    for i in range(row):
        for j in range(col):
            if matrix[i][j] != '':
                text += matrix[i][j]
    return text


# ------------------ RAIL FENCE CIPHER ------------------ #
def rail_fence_encrypt(text, rails):
    text = text.replace(" ", "").upper()
    fence = [['\n' for _ in range(len(text))] for _ in range(rails)]
    dir_down = False
    row, col = 0, 0

    for ch in text:
        if row == 0 or row == rails - 1:
            dir_down = not dir_down
        fence[row][col] = ch
        col += 1
        row += 1 if dir_down else -1

    cipher = ''
    for i in range(rails):
        for j in range(len(text)):
            if fence[i][j] != '\n':
                cipher += fence[i][j]
    return cipher

def rail_fence_decrypt(cipher, rails):
    cipher = cipher.replace(" ", "").upper()
    fence = [['\n' for _ in range(len(cipher))] for _ in range(rails)]
    dir_down = None
    row, col = 0, 0

    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == rails - 1:
            dir_down = False
        fence[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(rails):
        for j in range(len(cipher)):
            if fence[i][j] == '*' and index < len(cipher):
                fence[i][j] = cipher[index]
                index += 1

    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == rails - 1:
            dir_down = False
        if fence[row][col] != '\n':
            result.append(fence[row][col])
            col += 1
        row += 1 if dir_down else -1
    return "".join(result)


# ------------------ MAIN MENU ------------------ #
def main():
    while True:
        print("\n===== CIPHER PROGRAM =====")
        print("1. Playfair Cipher")
        print("2. Vigenère Cipher")
        print("3. Simple Columnar Cipher")
        print("4. Rail Fence Cipher")
        print("5. Exit")

        try:
            choice = int(input("Enter your choice (1-5): "))
        except ValueError:
            print("Invalid input! Please enter a number between 1 and 5.")
            continue

        if choice == 5:
            print("Exiting program. Goodbye!")
            break

        mode = input("Enter mode (E for Encrypt / D for Decrypt): ").upper()

        if choice == 1:
            text = input("Enter text: ")
            key = input("Enter key: ")
            if mode == 'E':
                print("Encrypted text:", playfair_encrypt(text, key))
            else:
                print("Decrypted text:", playfair_decrypt(text, key))

        elif choice == 2:
            text = input("Enter text: ")
            key = input("Enter key: ")
            if mode == 'E':
                print("Encrypted text:", vigenere_encrypt(text, key))
            else:
                print("Decrypted text:", vigenere_decrypt(text, key))

        elif choice == 3:
            text = input("Enter text: ")
            key = input("Enter key: ")
            if mode == 'E':
                print("Encrypted text:", columnar_encrypt(text, key))
            else:
                print("Decrypted text:", columnar_decrypt(text, key))

        elif choice == 4:
            text = input("Enter text: ")
            rails = int(input("Enter number of rails: "))
            if mode == 'E':
                print("Encrypted text:", rail_fence_encrypt(text, rails))
            else:
                print("Decrypted text:", rail_fence_decrypt(text, rails))

        else:
            print("Invalid choice! Please select 1–5.")

        # Continue or exit
        again = input("\nDo you want to perform another operation? (Y/N): ").upper()
        if again != 'Y':
            print("Exiting program. Goodbye!")
            break


if __name__ == "__main__":
    main()
'''
🧠 Overview
This program is a menu-driven Python application that allows the user to encrypt and decrypt text using four classical cipher techniques:

1️⃣ Playfair Cipher  
2️⃣ Vigenère Cipher  
3️⃣ Simple Columnar Cipher  
4️⃣ Rail Fence Cipher  

It supports mixed or numeric keys, handles odd-length text automatically, and allows multiple operations in a single session.

------------------------------------------------------------
⚙ Step-by-Step Explanation
------------------------------------------------------------

🧩 1. Helper Function — clean_key(key)
Purpose:
    - Sanitizes and converts the key into a consistent uppercase format.
Logic:
    - Loops through each character.
    - If letter → converts to uppercase.
    - If digit → converts to corresponding letter (1 → A, 2 → B, etc.).
    - Defaults to "KEY" if empty.
Use:
    - Ensures all ciphers receive a clean, uniform key.

------------------------------------------------------------
🧮 2. Playfair Cipher
------------------------------------------------------------
🔹 Function: generate_playfair_matrix(key)
    - Creates a 5×5 matrix from the key.
    - Replaces J with I.
    - Adds unique key letters, then fills remaining alphabet (A–Z without J).

Example (Key = "MONARCHY"):
M O N A R  
C H Y B D  
E F G I K  
L P Q S T  
U V W X Z  

🔹 Function: find_position(matrix, ch)
    - Finds row and column index of a letter.

🔹 Function: playfair_encrypt(text, key)
Steps:
    - Convert text to uppercase, remove spaces, replace J with I.
    - Add 'X' if text has odd length.
    - Split into pairs (digraphs).
    - Apply rules:
        • Same row → take letter to the right.  
        • Same column → take letter below.  
        • Rectangle rule → swap columns.
Example:
    Plaintext: HELLO  
    Key: MONARCHY  
    → Ciphertext: (depends on matrix)

🔹 Function: playfair_decrypt(cipher, key)
Reverse rules:
    - Same row → take left letter.
    - Same column → take upper letter.
    - Rectangle rule → swap columns again.

------------------------------------------------------------
🔐 3. Vigenère Cipher
------------------------------------------------------------
🔹 Function: generate_vigenere_key(text, key)
    - Repeats/trims key to match text length.
    Example: Text=HELLO, Key=ABC → Repeated Key=ABCAB

🔹 Function: vigenere_encrypt(text, key)
Formula:
    Ci = (Pi + Ki) mod 26
    - P: plaintext letter
    - K: key letter
    - C: ciphertext letter
Example:
    Plaintext = HELLO  
    Key = KEY  
    → Ciphertext = RIJVS

🔹 Function: vigenere_decrypt(cipher, key)
Formula:
    Pi = (Ci - Ki + 26) mod 26
    - Restores the original text.

------------------------------------------------------------
🧱 4. Simple Columnar Cipher
------------------------------------------------------------
🔹 Function: columnar_encrypt(text, key)
Idea:
    - Arrange text in a grid (rows × columns) → read column-wise using sorted key order.

Steps:
    - Remove spaces.
    - Clean key.
    - Sort key alphabetically and assign column numbers.
Example:
    Key = ZEBRA → Order = [E, A, B, R, Z]
    - Write text row by row.
    - Read columns in key order to get ciphertext.
    - Handles uneven text lengths automatically.

🔹 Function: columnar_decrypt(cipher, key)
Reverse process:
    - Create an empty grid.
    - Fill columns based on sorted key order.
    - Read row-wise → plaintext.

------------------------------------------------------------
🚄 5. Rail Fence Cipher
------------------------------------------------------------
🔹 Function: rail_fence_encrypt(text, rails)
Concept:
    - Write letters in a zigzag pattern over several rails.
Example (3 rails):

H . . . O . . . L . . .  
. E . L . W . R . D .  
. . L . . . O . . .  

Reading row by row → Cipher: HOLELWRDLO

Steps:
    - Create 2D list (rails × text length).
    - Traverse diagonally down and up.
    - Join rows → ciphertext.

🔹 Function: rail_fence_decrypt(cipher, rails)
    - Mark zigzag positions.
    - Fill cipher letters.
    - Traverse zigzag again → plaintext.

------------------------------------------------------------
🖥 6. main() — The Menu-Driven Interface
------------------------------------------------------------
Loop Process:
    1. Display menu:
        1. Playfair
        2. Vigenère
        3. Simple Columnar
        4. Rail Fence
        5. Exit
    2. Ask for choice and mode (Encrypt/Decrypt).
    3. Take input text and key (or rails).
    4. Call appropriate cipher function.
    5. Display output.
    6. Ask to continue or exit.

------------------------------------------------------------
✅ Program Highlights
------------------------------------------------------------
Feature                     | Explanation
-----------------------------|--------------------------------------------
Multiple Cipher Support      | Implements 4 classical algorithms
Input Flexibility            | Accepts letters and digits in keys
Automatic Handling           | Adds X for odd text, repeats key automatically
Error Handling               | Uses try-except for menu input
Looping Menu                 | Allows multiple operations in one session

------------------------------------------------------------
🗣 How to Explain Orally
------------------------------------------------------------
“This program implements four classical encryption techniques — Playfair, Vigenère, Columnar, and Rail Fence.
It uses a common helper function clean_key() to sanitize the key.
Each cipher has separate functions for encryption and decryption.
The Playfair cipher uses a 5×5 matrix with digraph rules.
The Vigenère cipher shifts letters based on a repeating key.
The Columnar cipher arranges text in a grid and reads by key order.
The Rail Fence cipher writes text in a zig-zag pattern over several rails.
Finally, the main() function provides a looping text menu for user interaction.”
'''
