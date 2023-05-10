import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class represents the client handler. It handles the communication with the client. It reads the file from the
 * server and sends it to the client.
 */
public class ClientHandler extends Thread {

    private final Socket client;
    private final boolean isConnected;
    private BigInteger sharedSecret;
    private final int algorithm;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private byte[] decryptedMessage;
    private String request;

    private static final String MAC_KEY = "Mas2142SS!±";

    /**
     * Creates a ClientHandler object by specifying the socket to communicate with the client. All the processing is
     * done in a separate thread.
     *
     * @param client the socket to communicate with the client
     *
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public ClientHandler ( Socket client , BigInteger sharedSecret , ObjectInputStream in , ObjectOutputStream out , int algorithm) throws IOException {
        this.client = client;
        this.sharedSecret = sharedSecret;
        this.in = in;
        this.out = out;
        this.algorithm = algorithm;
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
    }

    @Override
    public void run ( ) {
        super.run ( );
        try {
            while ( isConnected ) {
                // Reads the message to extract the path of the file
                Message message = ( Message ) in.readObject ( );
                //Make decryption with selected algorithm
                if (algorithm == 1) {
                    // Extracts and decrypt the message
                    decryptedMessage = Encryption.decryptMessage ( message.getMessage ( ) , sharedSecret.toByteArray ( ) );
                    // Computes the digest of the received message
                    byte[] computedDigest = Integrity.generateMAC ( decryptedMessage , MAC_KEY);
                    if ( ! Integrity.verifyMAC ( message.getMac ( ) , computedDigest ) ) {
                        throw new RuntimeException ( "The integrity of the message is not verified" );
                    }
                } else if (algorithm == 2) {
                    // Extracts and decrypt the message
                    decryptedMessage = Encryption.decryptMessageDES ( message.getMessage ( ) , sharedSecret.toByteArray ( ) );
                    // Computes the digest of the received message
                    byte[] computedDigest = Integrity.generateMAC ( decryptedMessage , MAC_KEY);
                    if ( ! Integrity.verifyMAC ( message.getMac ( ) , computedDigest ) ) {
                        throw new RuntimeException ( "The integrity of the message is not verified" );
                    }
                }
                request = new String ( decryptedMessage  );
                Pattern pattern = Pattern.compile ( "GET : (\\w+.txt)" );
                Matcher matcher = pattern.matcher ( request );
                boolean matchFound = matcher.find ( );
                if ( matchFound ) {
                    System.out.println(request);
                    File file = new File(RequestUtils.getAbsoluteFilePath(request));
                    if (file.exists()) {
                        // Reads the file and sends it to the client
                        byte[] content = FileHandler.readFile(RequestUtils.getAbsoluteFilePath(request));
                        sendFile( content , this.algorithm);
                    } else {
                        sendMessage("ERROR - FILE NOT FOUND");
                    }
                }
                else {
                    System.out.println("Invalid request");
                }
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
        //Make encryption with selected algorithm
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
    }

    /**
     * Sends the "ERROR - FILE NOT FOUND" to the client
     *
     * @param message the content of the message to send
     *
     * @throws Exception when an error occurs when sending the file
     */
    private void sendMessage ( String message ) throws Exception {
        //Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage(message.getBytes(), sharedSecret.toByteArray());
        //Generates the MAC
        byte[] mac = Integrity.generateMAC (message.getBytes(), MAC_KEY );
        Message response = new Message ( encryptedMessage , mac );
        out.writeObject ( response );
        out.flush ( );
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
