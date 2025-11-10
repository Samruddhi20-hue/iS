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