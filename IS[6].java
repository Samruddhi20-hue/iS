
import java.security.*;
import java.util.Base64;

public class DigitalSignature {
    public static void main(String[] args) {
        try {
            // Step 1: Generate RSA Key Pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            System.out.println("=== DIGITAL SIGNATURE IMPLEMENTATION ===");
            System.out.println("\nOriginal Message: This is a confidential message.");
            String message = "This is a confidential message.";

            // Step 2: Create a Signature object and initialize with private key
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(message.getBytes());

            // Step 3: Generate the digital signature
            byte[] signatureBytes = signer.sign();
            String signature = Base64.getEncoder().encodeToString(signatureBytes);
            System.out.println("\nGenerated Digital Signature: " + signature);

            // Step 4: Verify the digital signature
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(message.getBytes());

            boolean isVerified = verifier.verify(signatureBytes);
            System.out.println("\nSignature Verified: " + isVerified);

            // Optional: Display keys (Base64 encoded)
            System.out.println("\nPublic Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
/*PS C:\Users\HP> cd downloads
PS C:\Users\HP\downloads> cd C:\Users\HP\Downloads
>> 
PS C:\Users\HP\Downloads> javac DigitalSignature.java
>> 
PS C:\Users\HP\Downloads> java DigitalSignature
>> 
=== DIGITAL SIGNATURE IMPLEMENTATION ===

Original Message: This is a confidential message.

Generated Digital Signature: W4GN6+HakHVdBkbTI45yGjcJ7zQyuNHjfcStTxoLORS/m3TjvgGVGsPhSMHwR/ZT1EobNzYWwsVy1nO7K2FRruo4RVREEx1+dA8CiHnMnBoLa87UuCcrVV4bzc+C/rQBg+yUlC6THG/uvJRRAQJkjiugetolNY+Ynf9zeg9RT9wxQiFTkMA8Eik40RoMipwl6cVgrvYGg+CZ22/eeqtnPHYoB+tfmX9ZIP3K/DovWkhLhSeq+jK8oM/xOElmnTb8CrsuA0Ty3G+1Vrpcg78iejNS5GCjxA/CrLeyyHvXyzDV+FR68LUJWF66qfI+vVXM8O8Gj4FOH/CiGTx+fYKBnQ==

Signature Verified: true

Public Key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArssAhAK14agR/+e0lyGtcklIKWIyCUu6vMCXrbyyw06NZGbwzwTXkka4e0oHp9gYif4YV+Ce3Za74n/BbXEv2h4JvmJGJq4QTmYC2pGbWjb5WOBlOvlvoKgeE7ciXC5BPwdyxhce+wAg8VsYPa9g5tK4ryTo4mmbEI41p65YD/MQh0FNjgBOgq/cWEuIBj47wzM3scDV+RuY6nAZUfxeXqo4/XnP4SEC7kOwtbmLwFLPRlZE+X/GQF/ebKb+NcBAhHhTzgKIPc1rX6XdmGAINni7FPuaofFW58NCINlb+6xL1FXXW/V1tfwRCvhNazBN8FNha68KrViI6Ut2RidEGQIDAQAB
Private Key: MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuywCEArXhqBH/57SXIa1ySUgpYjIJS7q8wJetvLLDTo1kZvDPBNeSRrh7Sgen2BiJ/hhX4J7dlrvif8FtcS/aHgm+YkYmrhBOZgLakZtaNvlY4GU6+W+gqB4TtyJcLkE/B3LGFx77ACDxWxg9r2Dm0rivJOjiaZsQjjWnrlgP8xCHQU2OAE6Cr9xYS4gGPjvDMzexwNX5G5jqcBlR/F5eqjj9ec/hIQLuQ7C1uYvAUs9GVkT5f8ZAX95spv41wECEeFPOAog9zWtfpd2YYAg2eLsU+5qh8Vbnw0Ig2Vv7rEvUVddb9XW1/BEK+E1rME3wU2FrrwqtWIjpS3ZGJ0QZAgMBAAECggEAJ7G8LT58VYGYjNfuv/+K5xBTTeqZ2FiVULYf+/mFUyssmudxumGsHvDmhkEamfhOIlBM8O/2w/WuN1Kx94ujxVHa/pxMuA4Bb/xkm4RDlmozmAZlls38lqx3IB0PtYVfldO4MdogU/oEgSshxyhjxieGf2fPZ1N6Pnk9IBZMs1osV8/lJcHfLZRmOKZOi0cSIHN07WNZ56E7iK690XTq11IO6TSxjpjLQcVLz3EcEwTiPPjC73qasI+smBBdBH4oiU2yd+bXDA+Tsdn8fh/dV1GtAssWA9NyzUGgHTcR2Ho4hdjHPr0MLixofp2X7NhgUxGodK5irkI5b85awO3qcQKBgQDGNzkCvwdKjsShEL5/ltpBUmSuuIwIUxQgjA7sDf0PXEUta10qLL5K0NCnyjNPQlkW9/CG5F3T9CNTI86Lr1x7Q/Qmx1x31yK4NrxMdBDEfFlhUP28nSm18YS2MjwcwDxJbNjRUNUmW2i8bRszT4a8/Sgoj4ebTMKghDFB+B8nTQKBgQDhv79puW/ba3037Kt5n64OKTlc6Fg7Y+O9wh9bmeuFxdCqtVQs94yAplvE8mOM8CwqYniHBL+FOXbRXYEicLsZQMDLqLFDP5fM4og0TpmvPwzapLOhuzQwitXAtP0AxDwQGE7JQ5dtWSeotgvp0Vl+UE/INLTn26i/eT+FPz6h/QKBgCDwjmXZbxHB1gVaLf4wCIcwdRDgFE1R2RdrjxNFY9eIoupgXDQlCV6Pgw1POeWjBgEeJPeVvc36VWB8o9dsxfaqHUnQeZpkwx1P40zlQOAWNhhJCFGu4H6e60oH4Rt6Csq87u8h+roMGMSvcQS+44pGm8TZzVROlk1sim8HF85FAoGBAK9avbnHJF9BeIvnWC9qXM59MSS9CkRfzDjLQIZr4moQBY2EurUPOWF5V9F9It0IdpYZ1Vuz0X0P7P6mbjetb3gnN1s7Vy5QiH7K/Ff9Mh3RkQ+JXktj2h9WyMEfFWPyCmHKL/DggxCab1b6yfg++RBIHCD86AUuOD87VJ8RSHqVAoGBAKJ1feYtb8oGga/LLTBVVUectYY2NWqWaoGrElzIWNV/1KM1cMKJvfpc0CLEwohlaQPmmlsk/rVJMveAplLshQ+ylIGbmaKCsBGV1P2ZvzIOe93IAPTbVDgNxdDiHjpzbjw2+VJXIrtkI1MwXs2psYzGk9LjV5Z4Izz57WjHMH1s
PS C:\Users\HP\Downloads>  */