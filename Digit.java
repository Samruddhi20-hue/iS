/*
 * Assignment 6: Digital Signature implementation (single file).
 *
 * Provides RSA key generation, SHA-256 with RSA signing, and signature
 * verification through a lightweight interactive menu.
 */

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Digit {
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;
    private static final Scanner SCANNER = new Scanner(System.in, StandardCharsets.UTF_8);

    public static void main(String[] args) {
        while (true) {
            System.out.println("\nDigital Signature Demo");
            System.out.println("1. Generate RSA key pair");
            System.out.println("2. Sign a message");
            System.out.println("3. Verify a signature");
            
            System.out.println("4. Exit");
            System.out.print("Choose an option [1-5]: ");
            String choice = SCANNER.nextLine().trim();

            try {
                switch (choice) {
                    case "1":
                        generateKeys();
                        break;
                    case "2":
                        signFlow();
                        break;
                    case "3":
                        verifyFlow();
                        break;
                    case "4":
                        System.out.println("Goodbye!");
                        return;
                    default:
                        System.out.println("Please choose a valid option.");
                }
            } catch (Exception ex) {
                System.out.println("Operation failed: " + ex.getMessage());
            }
        }
    }

    private static void generateKeys() throws Exception {
        String privPath = prompt("Private key output [private.pem]: ", "private.pem");
        String pubPath = prompt("Public key output  [public.pem]: ", "public.pem");

        KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        generator.initialize(KEY_SIZE);
        KeyPair pair = generator.generateKeyPair();

        writePem(privPath, "PRIVATE KEY", pair.getPrivate().getEncoded());
        writePem(pubPath, "PUBLIC KEY", pair.getPublic().getEncoded());

        System.out.println("Keys saved to " + Paths.get(privPath).toAbsolutePath());
        System.out.println("             and " + Paths.get(pubPath).toAbsolutePath());
    }

    private static void signFlow() throws Exception {
        String privPath = prompt("Path to private key [private.pem]: ", "private.pem");
        if (!Files.exists(Path.of(privPath))) {
            throw new IllegalArgumentException("Private key not found: " + privPath);
        }
        System.out.print("Message to sign: ");
        String message = SCANNER.nextLine();

        PrivateKey privateKey = loadPrivateKey(Path.of(privPath));
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        String signatureB64 = Base64.getEncoder().encodeToString(signature.sign());

        System.out.println("Signature (Base64):\n" + signatureB64);
    }

    private static void verifyFlow() throws Exception {
        String pubPath = prompt("Path to public key [public.pem]: ", "public.pem");
        if (!Files.exists(Path.of(pubPath))) {
            throw new IllegalArgumentException("Public key not found: " + pubPath);
        }
        System.out.print("Message: ");
        String message = SCANNER.nextLine();
        System.out.print("Signature (Base64): ");
        String signatureB64 = SCANNER.nextLine().trim();

        PublicKey publicKey = loadPublicKey(Path.of(pubPath));
        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        boolean valid = verifier.verify(Base64.getDecoder().decode(signatureB64));

        System.out.println(valid
                ? "Signature is VALID for this message and public key."
                : "Signature is NOT valid.");
    }

    private static PrivateKey loadPrivateKey(Path path) throws Exception {
        byte[] der = readPem(path, "PRIVATE KEY");
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static PublicKey loadPublicKey(Path path) throws Exception {
        byte[] der = readPem(path, "PUBLIC KEY");
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
    }

    private static void writePem(String location, String type, byte[] der) throws Exception {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        String pem = "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
        Path path = Paths.get(location);
        Files.createDirectories(path.toAbsolutePath().getParent());
        Files.writeString(path, pem, StandardCharsets.UTF_8);
    }

    private static byte[] readPem(Path path, String type) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8).replace("\r", "").trim();
        String header = "-----BEGIN " + type + "-----";
        String footer = "-----END " + type + "-----";
        if (!pem.contains(header) || !pem.contains(footer)) {
            throw new IllegalArgumentException("PEM file does not contain " + type + " block");
        }
        String body = pem.substring(pem.indexOf(header) + header.length(), pem.indexOf(footer));
        body = body.replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static String prompt(String message, String defaultValue) {
        System.out.print(message);
        String input = SCANNER.nextLine().trim();
        return input.isEmpty() ? defaultValue : input;
    }

    
}
