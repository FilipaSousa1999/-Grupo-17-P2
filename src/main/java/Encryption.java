package src.main.java;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

/**
 * This class implements the encryption and decryption of messages.
 */
public class Encryption {
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
}
