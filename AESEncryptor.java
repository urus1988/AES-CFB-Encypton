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

public class AESEncryptor{
    private static byte[] encrypt(final SecretKey key,
                                  final IvParameterSpec iv,
                                  final byte[] value) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(value);
    }
    
    public static SecretKey getKeyFromPassword(char[] password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(password, salt.getBytes(), 65536, 256);
    SecretKey originalKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    return originalKey;
    }

    public static void main(String[] args) throws GeneralSecurityException{
        String pText = "AES sample java code by a zero staff";
        Console value = System.console();
        char[] password = value.readPassword("Enter password to encrypt data: ");

        //static salt, can take it from database
        String salt = "03022022";
        SecretKey secretKey = getKeyFromPassword(password, salt);

        //static iv, can input 
        final IvParameterSpec iv = new IvParameterSpec("12345678abcdefgh".getBytes());
        
        //encrypt
        byte[] cText = encrypt(secretKey, iv, pText.getBytes());
        String encodedText = Base64.getEncoder().encodeToString(cText);
        System.out.println(String.format("Encryted data is: %s",encodedText));

    }
}