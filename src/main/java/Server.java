import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class represents a server that receives a src.main.java.message from the clients. The server is implemented as a thread. Each
 * time a client connects to the server, a new thread is created to handle the communication with the client.
 */
public class Server implements Runnable {


    public static final String FILE_PATH = "server/files";
    private final ServerSocket server;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private final PrivateKey privateRSAKey;
    private final PublicKey publicRSAKey;
    private final boolean isConnected;

    private int algorithm_ser;

    /**
     * Constructs a Server object by specifying the port number. The server will be then created on the specified port.
     * The server will be accepting connections from all local addresses.
     *
     * @param port the port number
     *
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Server ( int port ) throws Exception {
        server = new ServerSocket ( port );
        //algorithm RSA
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate ( );
        this.publicRSAKey = keyPair.getPublic ( );
        savePublic_key(publicRSAKey);
        isConnected = true; // TODO: Check if this is necessary or if it should be controlled
    }

    @Override
    public void run ( ) {
        try {
            while ( isConnected ) {
                Socket client = server.accept ( );
                in = new ObjectInputStream ( client.getInputStream ( ) );
                out = new ObjectOutputStream ( client.getOutputStream ( ) );
                // Perform key distribution
                PublicKey clientPublicRSAKey = rsaKeyDistribution ( in );
                // Agree on a shared secret
                BigInteger sharedSecret = agreeOnSharedSecret ( clientPublicRSAKey );
                // Process the request
                process ( client , sharedSecret);
            }
            closeConnection ( );
        } catch ( Exception e ) {
            throw new RuntimeException ( e );
        }
    }

    /**
     * Processes the request from the client.
     *
     * @throws IOException if an I/O error occurs when reading stream header
     */
    private void process ( Socket client , BigInteger sharedSecret) throws IOException {
        ClientHandler clientHandler = new ClientHandler ( client , sharedSecret);
        clientHandler.start ( );
    }

    /**
     * Executes the key distribution protocol. The server will receive the public key of the client and will send its
     * own public key.
     *
     * @param in the input stream
     *
     * @return the public key of the client
     *
     * @throws Exception when the key distribution protocol fails
     */
    private PublicKey rsaKeyDistribution ( ObjectInputStream in ) throws Exception {
        // Extract the public key
        PublicKey clientPublicRSAKey = ( PublicKey ) in.readObject ( );
        // Send the public key
        sendPublicRSAKey ( );
        return clientPublicRSAKey;
    }

    /**
     * Sends the public key of the server to the client.
     *
     * @throws IOException when an I/O error occurs when sending the public key
     */
    private void sendPublicRSAKey ( ) throws IOException {
        out.writeObject ( publicRSAKey );
        out.flush ( );
    }

    /**
     * Performs the Diffie-Hellman algorithm to agree on a shared private key.
     *
     * @param clientPublicRSAKey the public key of the client
     *
     * @return the shared secret key
     *
     * @throws Exception when the key agreement protocol fails
     */
    private BigInteger agreeOnSharedSecret ( PublicKey clientPublicRSAKey ) throws Exception {
        // Generate a pair of keys
        BigInteger privateKey = DiffieHellman.generatePrivateKey ( );
        BigInteger publicKey = DiffieHellman.generatePublicKey ( privateKey );
        // Extracts the public key from the request
        BigInteger clientPublicKey = new BigInteger ( Encryption.decryptRSA ( ( byte[] ) in.readObject ( ) , clientPublicRSAKey ) );
        // Send the public key to the client
        sendPublicDHKey ( publicKey );
        // Generates the shared secret
        return DiffieHellman.computePrivateKey ( clientPublicKey , privateKey );
    }

    /**
     * Sends the public key to the client.
     *
     * @param publicKey the public key to be sent
     *
     * @throws Exception when the public key cannot be sent
     */
    private void sendPublicDHKey ( BigInteger publicKey ) throws Exception {
        out.writeObject ( Encryption.encryptRSA ( publicKey.toByteArray ( ) , this.privateRSAKey ) );
    }

    /**
     * Functions save public key
     *
     * @param publicKey value of public key
     *
     * @throws IOException error in I/O
     */
    private void savePublic_key(PublicKey publicKey) throws IOException {

        //File f1 = new File("./pki/public_keys/" + client.get_clientname()+"PUk.key");
        FileWriter f2 = new FileWriter("./pki/public_keys/serverPUk.key");
        f2.write(String.valueOf(publicKey));
        f2.close();
    }

    /**
     * Closes the connection and the associated streams.
     *
     * @throws IOException if an I/O error occurs when closing the socket
     */
    private void closeConnection ( ) {
        try {
            server.close ( );
        } catch ( IOException e ) {
            throw new RuntimeException ( e );
        }
    }

}