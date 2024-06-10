import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class ImageEncryptionExample {

    private static final String AES_ALGORITHM = "AES";

    public static void main(String[] args) {
        try {
            // Prompt user for secret key
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter the secret key (16 characters): ");
            String secretKeyStr = scanner.nextLine();

            // Validate and convert the user-entered secret key to bytes
            byte[] secretKeyBytes = validateAndConvertKey(secretKeyStr);

            // Create a SecretKey object from the user-entered secret key
            SecretKey secretKey = new SecretKeySpec(secretKeyBytes, AES_ALGORITHM);

            // Encrypt example image
            encryptImage("image.jpg", "encrypted_image.enc", secretKey);

            // Prompt user for decryption permission and secret key
            System.out.print("Image encrypted successfully. Do you want to decrypt the image? (yes/no): ");
            String response = scanner.nextLine().toLowerCase();

            if (response.equals("yes")) {
                System.out.print("Enter the secret key for decryption: ");
                String decryptionKeyStr = scanner.nextLine();
                byte[] decryptionKeyBytes = validateAndConvertKey(decryptionKeyStr);
                SecretKey decryptionKey = new SecretKeySpec(decryptionKeyBytes, AES_ALGORITHM);

                // Decrypt image and handle incorrect key
                try {
                    decryptImage("encrypted_image.enc", "decrypted_image.png", decryptionKey);
                    System.out.println("Image decrypted successfully. Check 'image.jpg'.");
                } catch (BadPaddingException e) {
                    System.out.println("Decryption failed. Incorrect secret key.");
                }
            } else {
                System.out.println("Image encryption completed. To decrypt, run the program again and enter 'yes'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] validateAndConvertKey(String keyStr) {
        if (keyStr.length() != 16) {
            throw new IllegalArgumentException("Secret key must be 16 characters long.");
        }
        return keyStr.getBytes();
    }

    private static void encryptImage(String inputFilePath, String outputFilePath, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] inputBytes = Files.readAllBytes(new File(inputFilePath).toPath());
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        Files.write(new File(outputFilePath).toPath(), encryptedBytes);
        System.out.println("Image encrypted successfully.");
    }

    private static void decryptImage(String inputFilePath, String outputFilePath, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encryptedBytes = Files.readAllBytes(new File(inputFilePath).toPath());
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        Files.write(new File(outputFilePath).toPath(), decryptedBytes);
    }
}
