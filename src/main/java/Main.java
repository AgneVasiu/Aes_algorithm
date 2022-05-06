import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    private static final String characterEncoding = "UTF-8";
    private static String cipherTransformation = " ";
    private static final String aesEncryptionAlgorithem = "AES";
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static String type;
    static SecureRandom rnd = new SecureRandom();

    static IvParameterSpec iv = new IvParameterSpec(rnd.generateSeed(16));
/**
 *Method to set Key
 */
    public static void setKey(String myKey) {
        MessageDigest identify = null;
        try {
            key = myKey.getBytes(characterEncoding);
            identify = MessageDigest.getInstance("SHA-1");
            key = identify.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Method to set what mode should be used
     */

    private static void setMode() {
        boolean status = true;
        while (status) {
            System.out.println("Pasirinkite moda: ");
            System.out.println("1.: CBC ");
            System.out.println("2.: CFB ");
            Scanner scanner = new Scanner(System.in);
            String choice = scanner.nextLine();
            if (choice.equals("1")) {
                type = "CBC";
                status = false;
            } else if (choice.equals("2")) {
                type = "CFB";
                status = false;
            }
        }
    }

    /**
     * Method for Encrypt Plain String Data
     */
    public static String encrypt(String plainText, String secret) {
        try {
            setKey(secret);
            setMode();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            if (type.equals("CBC")) {
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            } else if (type.equals("CFB")) {
                cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            }
            return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")));

        } catch (Exception E) {
            System.err.println("Encrypt Exception : " + E.getMessage());
        }
        return null;
    }

    /**
     * Method For Get encryptedText and Decrypted provided String
     */
    public static String decrypt(String encryptedText, String secret) {
        try {
            setKey(secret);
            setMode();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            if (type.equals("CBC")) {
                cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            } else if (type.equals("CFB")) {
                cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            }
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));

        } catch (Exception E) {
            System.err.println("decrypt Exception : " + E.getMessage());
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        int choice;
        String encyptStr = "";
        System.out.println("-----------------------");
        System.out.println("--AES algoritmas--");
        System.out.println("-----------------------");

        Scanner sc = new Scanner(System.in);
        System.out.println("Iveskie rakta:");
        String key = sc.nextLine();
        // encryptionKey = key;
        System.out.println("Iveskite teksta : ");
        String plainString = sc.nextLine();

        do {
            System.out.println("\nPasirinkite norima varianta\n1.Uzkriptuoti\n2.Atkriptuoti\n0.Iseiti\nPasirinkite(1,2): ");
            choice = sc.nextInt();
            sc.nextLine();
            if (choice == 1) {
                encyptStr = encrypt(plainString, key);
                System.out.println(plainString);
                System.out.println(encyptStr);
                saveToFile(encyptStr);
            } else if (choice == 2) {
                //encyptStr = encrypt(plainString, key);
                String decryptedString = decrypt(encyptStr,key);
                System.out.println(encyptStr);
                System.out.println(decryptedString);
            }

        } while (choice != 0);

    }

    private static void saveToFile(String encryptedString) throws FileNotFoundException {
        try (PrintWriter out = new PrintWriter("Text.txt")) {
            out.println(encryptedString);
        }
    }

}

