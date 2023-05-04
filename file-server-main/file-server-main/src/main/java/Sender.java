import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import  java.net.Socket;

import static jdk.internal.net.http.Exchange.ConnectionAborter.closeConnection;

/**
 * This class represents the sender of the message. It sends the message to the receiver by means of a socket. The use
 * of the Object streams enables the sender to send any kind of object.
 */
public class Sender {
    private static final String MAC_KEY = "Mas2142SS!±";

    private final Socket sender;
    private ObjectInputStream in;
    private ObjectOutputStream out;


    /**
     * Constructs a Sender object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @param port the port to connect to
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Sender(int port) throws IOException {
        client = new Socket(HOST, port);
        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());

    }
    /**
     * Sends a message to the receiver using the OutputStream of the socket. The message is sent as an object of the
     * {@link Message} class.
     *
     * @param message the message to send
     *
     * @throws Exception when the encryption or the integrity generation fails
     */
    public void sendMessage (String message) throws Exception {
        //Agree on a shared secret
        BigInteger secret = agreeOnSharedSecret();
        //Encrypts the message
        byte[] encryptedMessage = Encryption.encryptMessage(message.getBytes(), secret.toByteArray());
        //Generates the MAC
        byte[] mac = Integrity.generateMAC (message.getBytes(), MAC_KEY);
        //Creates the message object
        Message messageObj = new Message(encryptedMessage, mac);
        //Sends the encrypted message with MAC
        out.writeObject( messageObj );
        //Close connection
        closeConnection();

    }
    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @return the shared private key
     *
     * @throws Exception when the Diffie-Hellman algorithm fails
     */
    private BigInteger agreeOnSharedSecret ( ) throws Exception {
        // Generates a private key
        BigInteger privateKey = DiffieHellman.generatePrivateKey ( );
        BigInteger publicKey = DiffieHellman.generatePublicKey ( privateKey );
        // Sends the public key to the server
        sendPublicKey ( publicKey );
        // Waits for the server to send his public key
        BigInteger clientPublicKey = ( BigInteger ) in.readObject ( );
        // Generates the common private key
        return DiffieHellman.computePrivateKey ( clientPublicKey , privateKey );
    }
    /**
     * Sends the public key to the receiver.
     *
     * @param publicKey the public key to send
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicKey ( BigInteger publicKey ) throws Exception {
        out.writeObject ( publicKey );
    }

    /**
     * Closes the connection by closing the socket and the streams.
     *
     * @throws IOException when an I/O error occurs when closing the connection
     */
    private void closeConnection ( ) throws IOException {
        client.close ( );
        out.close ( );
        in.close ( );
    }
}
