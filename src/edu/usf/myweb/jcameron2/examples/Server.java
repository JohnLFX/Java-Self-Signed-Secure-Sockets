package edu.usf.myweb.jcameron2.examples;

import edu.usf.myweb.jcameron2.CertificateHelper;
import edu.usf.myweb.jcameron2.TrustOwnCAManager;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;

public class Server {

    public static void main(String[] args) throws Exception {

        //System.setProperty("javax.net.debug", "ssl,handshake");

        File caKeyStorePath = new File("server_ca.keystore");

        if (!caKeyStorePath.exists()) {

            System.out.println("CA Keystore not found at " + caKeyStorePath.getPath());
            System.out.println("Generating new CA keystore...");

            CertificateHelper.createCAKeyStore("Server CA", caKeyStorePath);

        }

        File keyStorePath = new File("server_cert.keystore");

        if (!keyStorePath.exists()) {

            System.out.println("Server Keystore not found at " + keyStorePath.getPath());
            System.out.println("Generating new server keystore...");

            CertificateHelper.createSignedCertificateKeyStore(
                    getExternalIP(),
                    "Server CA",
                    caKeyStorePath,
                    keyStorePath
            );

        }

        System.out.println("Loading KeyStore " + keyStorePath.getPath());

        char[] keyPassword = "".toCharArray();
        FileInputStream keyFile = new FileInputStream(keyStorePath);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(keyFile, keyPassword);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword);

        KeyManager keyManagers[] = keyManagerFactory.getKeyManagers();

        System.out.println("Initializing SSLContext...");

        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(keyManagers, new TrustManager[]{new TrustOwnCAManager(keyStore)}, new SecureRandom());

        keyFile.close();

        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();

        System.out.println("Binding server socket...");

        SSLServerSocket secureSocket = (SSLServerSocket) socketFactory.createServerSocket();
        secureSocket.setNeedClientAuth(true);
        secureSocket.bind(new InetSocketAddress("0.0.0.0", 0));

        Socket socket = secureSocket.accept();
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        out.writeUTF("Hello " + socket.getRemoteSocketAddress() + "!");
        out.flush();

        in.close();
        out.close();
        socket.close();

        System.out.println("Done");

    }

    private static String getExternalIP() throws IOException {
        URL url = new URL("http://checkip.amazonaws.com");
        BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));

        String ip = in.readLine();

        in.close();

        return ip;
    }

}
