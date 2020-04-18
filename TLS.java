package proj6;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/*
    TLS class in working with TLS SSLSocket connections, verifying what versions of TLS we
    are communicating with (i.e. 1.0, 1.1 ..) and testing their requests. Upon finish testing
    obtain the x500Principles used by the CA that signs the servers' certificates.
 */
public class TLS
{
    private static final int SSL_PORT = 443;
    private static final ArrayList<Certificate[]> sslCert = new ArrayList<>();
    private static final ArrayList<String> fileTxt = new ArrayList<>();
    private static Socket[] sockArr;
    private static final ArrayList<String> x500Principle = new ArrayList<>();

    /*
        method to obtain alternate names from the server we are connecting to.
        Runs the getMatch method and the getRobots method
     */
    private void getAlternateNames() throws IOException, CertificateParsingException
    {
        SSLSocket sslSock;              // SSLSocket for instance use

        int i = 0;                      // index to keep track of the Sockets[] used for getRobots

        /* for loop that loops through each url in the list.txt file */
        for (String hostName : TLS.fileTxt)
        {
            /* Creates a socket and connects to the hostName */
            Socket sock = SSLSocketFactory.getDefault().createSocket(hostName, SSL_PORT);
            sockArr[i] = sock; i++;     // adds the socket into the array and increases index;
            sslSock = (SSLSocket) sock; // casts the Socket to an SSLSocket

            /* adds the SSLSocket certificates to an ArrayList<Certificates[]> */
            sslCert.add(sslSock.getSession().getPeerCertificates());
        }

        int index = 0;                  // index to keep track of what certificate hostname we are accessing

        /* for loop to access each certificate array from the sslCert ArrayList */
        for (Certificate[] certArr : sslCert) {

            /* for loop to access each certificate in the certArray */
            for (Certificate cert : certArr) {
                /* casts the certificate to a X509Certificate */
                X509Certificate x509Cert = (X509Certificate) cert;

                /* if the x509Certificate is not null, enter statement */
                if (x509Cert.getSubjectAlternativeNames() != null) {
                    /* calls the getMatch method to see if there are any matches with the current hostname */
                    getMatch(x509Cert.getSubjectAlternativeNames(), index);
                    /* calls the getRobots method to see if the connection is a good or a bad one */
                    getRobots(sockArr[index]);
                    /* adds the current x509Certificate's X500Principle into an ArrayList<String> */
                    x500Principle.add(x509Cert.getIssuerX500Principal().toString());
                    index++;            // increment index
                }
            }
        }
    }

    /*
        method to find matches within the x509Certificate
        @param Collection<List<?>>   altNames    alternative names from the X509Certificate
        @param int                   index       current index in the file.txt
     */
    private void getMatch(Collection<List<?>> altNames, int index)
    {
        boolean match = false;          // if there is a match in the Collection

        /* for loop that goes through each List<?> in the Collection altNames */
        for (List<?> ahh : altNames)
        {
            /* grabs the alt name from that list */
            String altNameFromServer = (String) ahh.get(1);

            /* checks to see if the alt name is contained in the current file.txt line */
            if (altNameFromServer.endsWith(fileTxt.get(index)) ||
                    altNameFromServer.contains(fileTxt.get(index).substring(3)))
            {
                System.out.println(fileTxt.get(index) + " matched: " + altNameFromServer);
                match = true;
                break;
            }
        }

        /* if no match was found print message stating so */
        if (!match)
        {
            System.out.println(fileTxt.get(index) + " didn't match any name: " + altNames);
        }
    }

    /*
        method that gets the robots.txt's first line displaying the connection type and TLS used
        @param Socket   sock    the current host that we are accessing from the file.txt's socket
     */
    public void getRobots(Socket sock) throws IOException
    {
        /* message to send */
        byte[] robots = "GET /robots.txt HTTP/1.0\r\n\r\n".getBytes();

        /* in/out-put readers/streams to communicate with the server */
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        DataOutputStream out = new DataOutputStream(sock.getOutputStream());

        out.write(robots);
        System.out.println(in.readLine());

        out.close();
        in.close();
    }

    public static void main(String[] args)
    {
        TLS tls = new TLS();

        try
        {
            FileReader fr = new FileReader("F:\\JetBrainsWorkspace\\proj6\\src\\proj6\\list.txt");
            BufferedReader br = new BufferedReader(fr);
            String hostName =  "";

            while ((hostName = br.readLine()) != null) { fileTxt.add(hostName); }

            br.close();
            fr.close();

            sockArr = new Socket[fileTxt.size()];
            tls.getAlternateNames();
        }
        catch (IOException | CertificateParsingException e)
        {
            e.printStackTrace();
        }

        for (String s : x500Principle)
        {
            System.out.println(s);
        }
    }
}
