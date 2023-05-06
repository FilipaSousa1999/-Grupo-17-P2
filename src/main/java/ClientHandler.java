import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {

    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final Socket client;
    private final boolean isConnected;
    private BigInteger sharedSecret;
    private int algorithm;

    private static final String MAC_KEY = "Mas2142SS!±";

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler ( Socket client , BigInteger sharedSecret) throws IOException {
        this.client = client;
        this.sharedSecret = sharedSecret;
        in = new ObjectInputStream ( client.getInputStream ( ) );
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
    }

    @Override
    public void run ( ) {
        super.run ( );
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                Message message = ( Message ) in.readObject ( );

                if (this.algorithm == 1) {
                    // Extracts and decrypt the message
                    byte[] decryptedMessage = Encryption.decryptMessage ( message.getMessage ( ) , sharedSecret.toByteArray ( ) );
                    // Computes the digest of the received message
                    byte[] computedDigest = Integrity.generateMAC ( decryptedMessage , MAC_KEY);
                    if ( ! Integrity.verifyMAC ( message.getMac ( ) , computedDigest ) ) {
                        throw new RuntimeException ( "The integrity of the message is not verified" );
                    }
                } else if (this.algorithm == 2) {
                    // Extracts and decrypt the message
                    byte[] decryptedMessage = Encryption.decryptMessageDES ( message.getMessage ( ) , sharedSecret.toByteArray ( ) );
                    // Computes the digest of the received message
                    byte[] computedDigest = Integrity.generateMAC ( decryptedMessage , MAC_KEY);
                    if ( ! Integrity.verifyMAC ( message.getMac ( ) , computedDigest ) ) {
                        throw new RuntimeException ( "The integrity of the message is not verified" );
                    }
                }

                // Extracts and decrypt the message
                // byte[] decryptedMessage = Encryption.decryptMessage ( message.getMessage ( ) , sharedSecret.toByteArray ( ) );
                // Computes the digest of the received message
                //byte[] computedDigest = Integrity.generateMAC ( decryptedMessage , MAC_KEY);
                // Verifies the integrity of the message
                // if ( ! Integrity.verifyMAC ( message.getMac ( ) , computedDigest ) ) {
                //    throw new RuntimeException ( "The integrity of the message is not verified" );
                //}
                String request = new String ( message.getMessage ( ) );
                // Reads the file and sends it to the client
                byte[] content = FileHandler.readFile ( RequestUtils.getAbsoluteFilePath ( request ) );
                sendFile ( content, this.algorithm  );

            }
            // Close connection
            closeConnection ( );
        } catch ( IOException | ClassNotFoundException e ) {
            // Close connection
            closeConnection ( );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sends the file to the client
     *
     * @param content the content of the file to send
     *
     * @throws Exception when an error occurs when sending the file
     */
    private void sendFile ( byte[] content, int algorithm  ) throws Exception {
        if (algorithm == 1) {
            byte[] encryptedMessage = Encryption.encryptMessage(content, sharedSecret.toByteArray());
            byte[] mac = Integrity.generateMAC (content, MAC_KEY );
            Message response = new Message ( encryptedMessage , mac );
            out.writeObject ( response );
            out.flush ( );
        } else if (algorithm == 2) {
            byte[] encryptedMessage = Encryption.encryptMessageDES(content, sharedSecret.toByteArray());
            byte[] mac = Integrity.generateMAC (content, MAC_KEY );
            Message response = new Message ( encryptedMessage , mac );
            out.writeObject ( response );
            out.flush ( );
        }
        //Encrypts the content
        //byte[] encryptedMessage = Encryption.encryptMessage(content, sharedSecret.toByteArray());
        //Generates the MAC

        //Message response = new Message ( encryptedMessage , mac );
        //out.writeObject ( response );
        //out.flush ( );
    }


    /**
     * Closes the connection by closing the socket and the streams.
     */
    private void closeConnection ( ) {
        try {
            client.close ( );
            out.close ( );
            in.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}
