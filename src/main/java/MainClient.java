import java.util.Scanner;

public class MainClient {

    public static void main ( String[] args ) throws Exception {
        int a = 0;
        while (a==5) {
            Client client = new Client( 8000);
            Scanner userInput = new Scanner ( System.in );
            System.out.println ( "Please enter your name" );
            String userName = userInput.nextLine ( );
            client.setClientname(userName);
            // Create folder where we will store private key
            client.CreateFolder(userName);
            client.CreateFolderPrivate_keys(userName);
            //Save keys
            client.savePrivate_key(client.getPrivateRSAKey(), userName);
            client.savePublic_key(client.getPublicRSAKey(), userName);
            while (a<5) {
                a++;
                System.out.println ( "GET : nome do ficheiro pretendido.txt" );
                String request = userInput.nextLine ( );
                client.sendMessage ( request );
            }
        }

    }

}