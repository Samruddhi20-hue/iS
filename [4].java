// Assignment No: 4
// Program: Implement MD5 Hashing - Calculate the MD5 message digest of a text input using Java.

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class MD5Hashing {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("===== MD5 Hashing Program =====");
        System.out.print("Enter text to hash: ");
        String input = sc.nextLine();

        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // Add the input bytes to digest
            md.update(input.getBytes());

            // Get the hash's bytes
            byte[] digestBytes = md.digest();

            // Convert bytes into hexadecimal format
            StringBuilder hexString = new StringBuilder();
            for (byte b : digestBytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }

            // Print the resulting hash
            System.out.println("MD5 Hash Value: " + hexString.toString());
        } 
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error: MD5 algorithm not found!");
        }
    }
}
/*PS C:\Users\HP\Downloads> javac MD5Hashing.java
>> 
javac : The term 'javac' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a 
path was included, verify that the path is correct and try again.
At line:1 char:1
+ javac MD5Hashing.java
+ ~~~~~
    + CategoryInfo          : ObjectNotFound: (javac:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
 
PS C:\Users\HP\Downloads> java MD5Hashing
>> 
java : The term 'java' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path 
was included, verify that the path is correct and try again.
At line:1 char:1
+ java MD5Hashing
+ ~~~~
    + CategoryInfo          : ObjectNotFound: (java:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\HP\Downloads> */
/*
🧩 Step-by-step Explanation of MD5 Hashing Program

1️⃣ Imports and Setup
-------------------------------------------------
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

- MessageDigest is a Java class that implements hashing algorithms such as MD5, SHA-1, SHA-256, etc.
- NoSuchAlgorithmException handles the rare situation where MD5 algorithm is not available.
- Scanner is used to read input from the user.

👉 In simple words:
   “We import Java classes to read user input and compute the hash.”


2️⃣ Main Class and Input
-------------------------------------------------
Scanner sc = new Scanner(System.in);
System.out.println("===== MD5 Hashing Program =====");
System.out.print("Enter text to hash: ");
String input = sc.nextLine();

- Scanner reads the line typed by the user.
- The entered text is stored in the variable ‘input’.

👉 In simple words:
   “We ask the user to enter text and store it for hashing.”


3️⃣ Creating MessageDigest Object for MD5
-------------------------------------------------
MessageDigest md = MessageDigest.getInstance("MD5");

- This creates a MessageDigest object configured to use MD5.
- If "MD5" is not supported (very unlikely), Java throws NoSuchAlgorithmException.

👉 In simple words:
   “We request an MD5 object from Java’s security library.”


4️⃣ Feeding Input Bytes to Digest
-------------------------------------------------
md.update(input.getBytes());

- input.getBytes() converts the input string into a byte array (binary form).
- md.update(...) passes those bytes into the MD5 hashing algorithm.

👉 In simple words:
   “We convert the text to bytes and give those bytes to the MD5 function.”


5️⃣ Computing the Digest Bytes
-------------------------------------------------
byte[] digestBytes = md.digest();

- md.digest() completes the hashing process.
- It returns a 16-byte MD5 hash value (raw binary form).

👉 In simple words:
   “This function computes the hash and gives the final byte result.”


6️⃣ Converting Bytes to Hexadecimal String
-------------------------------------------------
StringBuilder hexString = new StringBuilder();
for (byte b : digestBytes) {
    hexString.append(String.format("%02x", b & 0xff));
}
System.out.println("MD5 Hash Value: " + hexString.toString());

- MD5 hash bytes are not readable, so we convert each byte to its hexadecimal (base-16) representation.
- b & 0xff makes sure we treat the byte as an unsigned value between 0–255.
- "%02x" ensures each byte is printed as two lowercase hex digits (adding a leading zero if needed).
- Finally, we print the 32-character hexadecimal hash string.

👉 In simple words:
   “We change the hash bytes into a readable 32-digit hexadecimal form.”


7️⃣ Error Handling
-------------------------------------------------
catch (NoSuchAlgorithmException e) {
    System.out.println("Error: MD5 algorithm not found!");
}

- This catches the exception if the algorithm “MD5” is not available.
- In normal cases, this never happens since MD5 is always supported in Java.

👉 In simple words:
   “We handle the rare case where MD5 isn’t available.”


🗣 Viva Explanation (Say this smoothly)
-------------------------------------------------
“The program reads input from the user using Scanner. 
It then creates a MessageDigest object for MD5 and feeds the input bytes to it. 
The digest() method computes the 16-byte message digest, which is then converted into a 32-character hexadecimal string and displayed as the final MD5 hash.”

“MD5 always produces the same hash for the same input, but it’s not secure for passwords or digital signatures because collisions can occur.”


⚠ Security Note
-------------------------------------------------
- MD5 is not recommended for secure hashing.
- It is vulnerable to collisions (two different inputs giving same hash).
- It should NOT be used for password hashing, encryption, or digital signatures.
- Use SHA-256 or secure algorithms (PBKDF2, bcrypt, scrypt, Argon2) instead.

👉 In simple words:
   “MD5 is fine for checksums but not safe for real security.”


🧪 Example Hash Outputs (for Viva)
-------------------------------------------------
MD5("hello")    → 5d41402abc4b2a76b9719d911017c592
MD5("password") → 5f4dcc3b5aa765d61d8327deb882cf99

👉 In simple words:
   “For example, MD5 of hello is 5d41402abc4b2a76b9719d911017c592.”


✅ Quick Checklist for Viva / Exams
-------------------------------------------------
✔ Input text → convert to bytes.
✔ Create MessageDigest object for “MD5”.
✔ Call md.update() to feed data.
✔ Call md.digest() to compute hash bytes.
✔ Convert bytes to hexadecimal format.
✔ Print final MD5 hash.
✔ Handle NoSuchAlgorithmException safely.
✔ Mention MD5 is weak for security purposes.

*/