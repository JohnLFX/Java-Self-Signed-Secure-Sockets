package edu.usf.myweb.jcameron2.examples;

import edu.usf.myweb.jcameron2.TrustOwnCAManager;

import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.SecureRandom;

public class Client {

    private static final String HOST_IP = "0.0.0.0";
    private static final int HOST_PORT = 0;

    public static void main(String[] args) throws Exception {

        //System.setProperty("javax.net.debug", "ssl,handshake");

        System.out.println("Loading our keystore...");

        char[] keyPassword = "".toCharArray();
        FileInputStream keyFile = new FileInputStream(new File("client.keystore"));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(keyFile, keyPassword);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword);

        KeyManager keyManagers[] = keyManagerFactory.getKeyManagers();

        System.out.println("Initializing SSLContext...");

        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(keyManagers, new TrustManager[]{new TrustOwnCAManager(keyStore)}, new SecureRandom());

        keyFile.close();

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        SSLSocket socket = (SSLSocket) socketFactory.createSocket();
        socket.setNeedClientAuth(true);

        System.out.println("Connecting...");

        socket.connect(new InetSocketAddress(HOST_IP, HOST_PORT));

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        System.out.println("Connected to " + socket.getSession().getPeerHost() + " using " + socket.getSession().getCipherSuite());
        System.out.println("Welcome message: " + in.readUTF());

        //Networking stuff

        in.close();
        out.close();
        socket.close();

        System.out.println("Done");

    }

}
