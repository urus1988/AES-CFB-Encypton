import java.util.Base64;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESCrypto {
    //Generate AES key
    public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

    private static byte[] encrypt(final SecretKey key,
                                  final IvParameterSpec iv,
                                  final byte[] value) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(value);
    }
    
    private static String decrypt(final SecretKey key,
                                  final IvParameterSpec iv,
                                  final byte[] encrypted) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(encrypted);
        return new String(plainText);
    }
    
    public static void main(final String[] args) throws GeneralSecurityException {
        SecretKey secretKey = getAESKey(256);
        String pText = "AES sample java code. Encrypt and decrypt in same program";
        
        //Generate the same IV once:
        final IvParameterSpec iv = new IvParameterSpec(new byte[16]);

        //Encrypt
        byte[] cText = encrypt(secretKey, iv, pText.getBytes());
        String encodedText = Base64.getEncoder().encodeToString(cText);
        System.out.println(String.format("Encrypted text is: %s", encodedText));

        //Decrypt
        String dText = decrypt(secretKey, iv, cText);
        System.out.println(String.format("Original text is: %s", dText));
    }
}