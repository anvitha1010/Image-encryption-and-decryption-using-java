import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class ImageEncryption {

    private static final String AES_ALGORITHM = "AES";

    public static void main(String[] args) {
        try {
            // Generate a random secret key for AES
            SecretKey secretKey = generateAESKey();

            // Encrypt image
            encryptImage("image.jpg", "encrypted_image.enc", secretKey);

            // Prompt user for decryption permission
            Scanner scanner = new Scanner(System.in);
            System.out.print("Do you want to decrypt the image? (yes/no): ");
            String response = scanner.nextLine().toLowerCase();

            if (response.equals("yes")) {
                // Decrypt image
                decryptImage("encrypted_image.enc", "image.jpg", secretKey);
                System.out.println("Image decrypted successfully.");
            } else {
                System.out.println("Image encryption completed. To decrypt, run the program again and enter 'yes'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(128); // Use 128-bit key size (AES-128)
        return keyGen.generateKey();
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
