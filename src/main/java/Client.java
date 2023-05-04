import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class represents the sender of the src.main.java.message. It sends the src.main.java.message to the receiver by means of a socket. The use
 * of the Object streams enables the sender to send any kind of object.
 */
public class Client {
    private static final String MAC_KEY = "Mas2142SS!±";
    private static final String HOST = "0.0.0.0";
    private final Socket client;
    private String clientname;
    File file;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private final PublicKey serverPublicRSAKey;


    /**
     * Constructs a src.main.java.Client object by specifying the port to connect to. The socket must be created before the sender can
     * send a src.main.java.message.
     *
     * @param port the port to connect to
     * @throws IOException when an I/O error occurs when creating the socket
     */
    public Client(int port) throws Exception {
        client = new Socket(HOST, port);
        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());
        KeyPair keyPair = Encryption.generateKeyPair ( );
        this.privateRSAKey = keyPair.getPrivate ( );
        this.publicRSAKey = keyPair.getPublic ( );
        // Performs the RSA key distribution
        serverPublicRSAKey = rsaKeyDistribution ( );
    }
    /**
     * Sends a src.main.java.message to the receiver using the OutputStream of the socket. The src.main.java.message is sent as an object of the
     * {@link Message} class.
     *
     * @param message the src.main.java.message to send
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
        Message messageObj = new Message ( encryptedMessage , mac );
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
     * Executes the key distribution protocol. The client sends its public key to the server and receives the public
     * key of the server.
     *
     * @return the public key of the server
     *
     * @throws Exception when the key distribution protocol fails
     */
    private PublicKey rsaKeyDistribution ( ) throws Exception {
        // Sends the public key
        sendPublicRSAKey ( );
        // Receive the public key of the server
        return ( PublicKey ) in.readObject ( );
    }

    /**
     * Sends the public key of the client to the server.
     *
     * @throws IOException when an I/O error occurs when sending the public key
     */
    private void sendPublicRSAKey ( ) throws IOException {
        out.writeObject ( publicRSAKey );
        out.flush ( );
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

    public String get_clientname(){
        return this.clientname;
    }

    /**
     * Function creates private file with sender's name
     *
     * @param clientname value to create file with sender's name
     */
    public void CreateFolder(String clientname) {
        file = new File("./" +clientname);
        //Creating a folder using mkdir() method
        boolean bool = file.mkdir();
        if(bool){
            System.out.println("Folder with client name is created successfully");
        }else{
            System.out.println("Error Found!");
        }
    }

    /**
     * Function creates private file with sender's name
     *
     * @param clientname value to create private file with sender's name
     */
    public void CreateFolderPrivate_keys(String clientname) {
        File f1 = new File("./" +clientname+"/private");
        //Creating a folder using mkdir() method
        boolean bool = f1.mkdir();
        if(bool){
            System.out.println("Folder private is created successfully");
        }else{
            System.out.println("Error Found!");
        }
    }

    /**
     * Functions saves private key
     *
     * @param privateKey value of private key
     *
     * @param userName we need to know a client's name to save a private key with client's name
     *
     * @throws IOException
     */
    public void savePrivate_key(PrivateKey privateKey, String userName) throws IOException {
        FileWriter f1 = new FileWriter("./" + userName+"/private/" + userName+"Prk.key");
        f1.write(String.valueOf(privateKey));
        f1.close();
    }

    /**
     * Functions create file with client's name and saves public key
     *
     * @param publicKey value of public key
     *
     * @param userName we need to know a client's name to save a public key with client's name
     *
     * @throws IOException error in I/O
     */
    public void savePublic_key(PublicKey publicKey, String userName) throws IOException {

        /*File f1 = new File("./pki/public_keys/" + client.get_clientname()+"PUk.key");
        //Creating a folder using mkdir() method
        boolean bool = f1.mkdir();
        if(bool){
            System.out.println("Folder private is created successfully");
        }else{
            System.out.println("Error Found!");
        }*/

        FileWriter f2 = new FileWriter("./pki/public_keys/" + userName+"PUk.key");
        f2.write(String.valueOf(publicKey));
        f2.close();
    }

    public void setClientname(String clientname) {
        this.clientname = clientname;
    }

    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    public PrivateKey getPrivateRSAKey() {
        return privateRSAKey;
    }
}
