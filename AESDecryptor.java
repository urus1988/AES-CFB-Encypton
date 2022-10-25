import java.util.Base64;
import java.io.Console;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.spec.KeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESDecryptor{
    private static String decrypt(final SecretKey key,
                                  final IvParameterSpec iv,
                                  final byte[] encrypted) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(encrypted);
        return new String(plainText);
    }

    public static SecretKey getKeyFromPassword(char[] password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(password, salt.getBytes(), 65536, 256);
    SecretKey originalKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    return originalKey;
    }

    public static void main(String[] args) throws GeneralSecurityException{
        Console value = System.console();
        char[] password = value.readPassword("Enter password to decrypt data: ");
        String encodedText = "R+n91H0JKQwBFgsXvtEDUrCeSm5iP1oMUvBONWhdq1EdEy6vttxNczFLWFrVPwVZ";

        //static salt, can take it from database
        String salt = "03022022";
        SecretKey secretKey = getKeyFromPassword(password, salt);

        //static iv, can input 
        final IvParameterSpec iv = new IvParameterSpec("12345678abcdefgh".getBytes());
        
        //Decrypt it
        byte[] cipherText = Base64.getDecoder().decode(encodedText);
        String original = decrypt(secretKey, iv, cipherText);
        System.out.println(String.format("Original data is: %s",original));

    }
}