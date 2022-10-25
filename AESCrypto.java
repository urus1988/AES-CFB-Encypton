import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class AESCrypto {
    
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

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
        return new String(plainText, UTF_8);
    }
    
    public static void main(final String[] args) throws GeneralSecurityException {
        SecretKey secretKey = getAESKey(256);
        String pText = "VPBank AES sample java code, change it as your purpose";
        
        //Generate the same IV once:
        final IvParameterSpec iv = new IvParameterSpec(new byte[16]);

        //Encrypt
        byte[] cText = encrypt(secretKey, iv, pText.getBytes(UTF_8));
        System.out.println(String.format("Encrypted text is: %s", hex(cText)));

        //Decrypt
        String dText = decrypt(secretKey, iv, cText);
        System.out.println(String.format("Original text is: %s", dText));

        System.out.println(String.format("Key to encrypt is: %s", hex(secretKey.getEncoded())));
        System.out.println(secretKey);
        System.out.println(secretKey.getEncoded());
        System.out.println(hex(secretKey.getEncoded()));

        String abc = hex(secretKey.getEncoded());

        
        //System.out.println(Arrays.equals(value, decrypt(k, iv, encrypt(k, iv, value))));
    }
}