import java.io.Serializable;

/**
 * This class represents a message object that is sent to the server by the client.
 */
public class message implements Serializable {

    private final byte[] message;


    private final byte[] mac;

    /**
     * Constructs a Message object by specifying the message bytes that will be sent to the server and the message
     * authentication code (MAC).
     *
     * @param message the message that is sent to the server
     * @param mac     the message authentication code (MAC)
     */
    public Message ( byte[] message , byte[] mac ) {
        this.message = message;
        this.mac = mac;
    }


    /**
     * Gets the message string.
     *
     * @return the message string
     */
    public byte[] getMessage ( ) {

        return message;
    }
    public byte[] getMac ( ) {
        return mac;
    }
}