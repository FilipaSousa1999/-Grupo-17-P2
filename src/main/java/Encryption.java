import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * This class implements the encryption and decryption of messages.
 */
public class Encryption {

    public static KeyPair generateKeyPair ( ) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ( "RSA" );
        keyPairGenerator.initialize ( 2048 );
        return keyPairGenerator.generateKeyPair ( );
    }

    public static byte[] encryptRSA ( byte[] message , Key key ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.ENCRYPT_MODE , key );
        return cipher.doFinal ( message );
    }

    public static byte[] decryptRSA ( byte[] message , Key key ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "RSA" );
        cipher.init ( Cipher.DECRYPT_MODE , key );
        return cipher.doFinal ( message );
    }

    public static KeyPair generateKeyPairDES ( ) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance ( "DES" );
        keyPairGenerator.initialize ( 2048 );
        return keyPairGenerator.generateKeyPair ( );
    }

    public static byte[] encryptDES ( byte[] message , Key key ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "DES" );
        cipher.init ( Cipher.ENCRYPT_MODE , key );
        return cipher.doFinal ( message );
    }

    public static byte[] decryptDES ( byte[] message , Key key ) throws Exception {
        Cipher cipher = Cipher.getInstance ( "DES" );
        cipher.init ( Cipher.DECRYPT_MODE , key );
        return cipher.doFinal ( message );
    }

    /**
     * @param message   the src.main.java.message to be encrypted
     * @param secretKey the secret key used to encrypt the src.main.java.message
     *
     * @return the encrypted src.main.java.message as an array of bytes
     *
     * @throws Exception when the decryption fails
     */
    public static byte[] decryptMessage ( byte[] message , byte[] secretKey ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( 16 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec( secretKeyPadded , "AES" );
        Cipher cipher = Cipher.getInstance ( "AES/ECB/PKCS5Padding" );
        cipher.init ( Cipher.DECRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }
    /**
     * @param message   the src.main.java.message to be decrypted
     * @param secretKey the secret key used to decrypt the src.main.java.message
     *
     * @return the decrypted src.main.java.message as an array of bytes
     *
     * @throws Exception when the encryption fails
     */
    public static byte[] encryptMessage ( byte[] message , byte[] secretKey ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( 16 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , "AES" );
        Cipher cipher = Cipher.getInstance ( "AES/ECB/PKCS5Padding" );
        cipher.init ( Cipher.ENCRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }



    public static byte[] decryptMessageDES ( byte[] message , byte[] secretKey ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate(16).put(secretKey).array();
        SecretKeySpec secreteKeySpec = new SecretKeySpec(secretKeyPadded, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secreteKeySpec);
        return cipher.doFinal(message);
    }

    public static byte[] encryptMessageDES ( byte[] message , byte[] secretKey ) throws Exception {
        byte[] secretKeyPadded = ByteBuffer.allocate ( 16 ).put ( secretKey ).array ( );
        SecretKeySpec secreteKeySpec = new SecretKeySpec ( secretKeyPadded , "DES" );
        Cipher cipher = Cipher.getInstance ( "DES/ECB/PKCS5Padding" );
        cipher.init ( Cipher.ENCRYPT_MODE , secreteKeySpec );
        return cipher.doFinal ( message );
    }
}
