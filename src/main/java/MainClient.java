import java.util.Scanner;

public class MainClient {

    public static void main ( String[] args ) throws Exception {
        Client client = new Client( 8000 );
        Scanner userInput = new Scanner ( System.in );
        System.out.println ( "Write the message to send" );
        String message = userInput.nextLine ( );
        client.sendMessage ( message );
    }

}