package ckcs.classes;

import ckcs.interfaces.RequestCodes;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class GroupMember {
    
    final private UUID memberID; //randomly assigned
    private UUID serverID;
    private SecretKey key; //Group Controller key exchange 
    private SecretKey groupKey;
    private int parentCode; //Should be obtained from GroupController via LogicalTree
    private int globalPort; //the port multicast group globally sends too
    private InetAddress multicastAddress;
    private int port; //member's unqiue port to communicate with server
    private InetAddress address;
    private boolean isConnected; 
    
    
    public GroupMember(final int port) {
        this(UUID.randomUUID(), port);              
    }
    
    public GroupMember(UUID Id, int port) {
        this.memberID = Id;
        this.port = port;
    }

    public void requestJoin(final InetAddress address, final int portNumber) {
        try {
            try (Socket socket = new Socket(address, portNumber);
                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
                
                out.writeInt(RequestCodes.REQUEST_JOIN);
                String message = in.readUTF();
                String parts[] = message.split("::");
                serverID = UUID.fromString(parts[0]);
                int N1Received = Integer.parseInt(parts[1]);
                
                int N2 = (int)(1000 * Math.random() * Math.random());
                message = "" + N1Received + "::" + memberID.toString() + "::" + N2 + "::" + 
                        port + "::" + address.getHostAddress();
                out.writeUTF(message);
                this.key = Security.ECDHKeyAgreement(in, out);
                
                int length = in.readInt();
                byte[] received = new byte[length];
                in.readFully(received);
                message = new String(Security.AESDecrypt(key, received), StandardCharsets.UTF_8);
                parts = message.split("::");
                int N2Received = Integer.parseInt(parts[1]);
                UUID memID = UUID.fromString(parts[2]);
                if (N2Received != N2 || !memID.equals(memberID)) {
                    System.out.println("Connection Failed -- Back Out");
                    return;
                }
                
                length = in.readInt();
                received = new byte[length];
                in.read(received);
                message = new String(Security.AESDecrypt(key, received), StandardCharsets.UTF_8);
                parts = message.split("::");
                parentCode = Integer.parseInt(parts[0]);
                multicastAddress = InetAddress.getByName(parts[1]);
                System.out.println(multicastAddress.getHostAddress());
                globalPort = Integer.parseInt(parts[2]);
                
                BigInteger big = BigInteger.valueOf(parentCode);
                byte[] encryptedMessage = Security.AESEncrypt(key, big.toByteArray());
                length = encryptedMessage.length;
                out.writeInt(length);
                out.write(encryptedMessage);
                
                length = in.readInt();
                received = new byte[length];
                in.read(received);
                groupKey = new SecretKeySpec(Security.AESDecrypt(key, received), "AES");
                isConnected = true;
                listenToKeyServer();
                listenToMulticast(globalPort);
                System.out.println("Connection Successful! Added to group");
            }
        } catch (IOException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    public void requestLeave(final InetAddress address, final int portNumber) {
        try {
            try (Socket socket = new Socket(address, portNumber); 
                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {                
                out.writeInt(RequestCodes.REQUEST_LEAVE);
                String message = in.readUTF();
                String parts[] = message.split("::");
                UUID servID = UUID.fromString(parts[0]);
                if (!servID.equals(serverID)) {
                    System.out.println("Connection Failed -- Backout");
                    return;
                }
                int N1Received = Integer.parseInt(parts[1]);
                
                int N2 = (int)(100 * Math.random() * Math.random());
                message = "" + N1Received + "::" + memberID.toString() + "::" + N2;
                out.writeUTF(message);
                int N2Received = in.readInt();
                if (N2 == N2Received) {
                    System.out.println("Successful Leave");
                }
                isConnected = false;
            }
        } catch (IOException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

  
    public void sendMessage() {
    }

    private void listenToKeyServer() {
        Thread keyServerListener = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    ServerSocket fromServer = new ServerSocket(port);
                    while (isConnected) {
                      Socket socket = fromServer.accept();
                      DataInputStream in = new DataInputStream(socket.getInputStream());
                      int code = in.readInt();
                      switch (code) {
                          case RequestCodes.KEY_UPDATE_JOIN:
                              handleJoinUpdate();
                              break;
                          case RequestCodes.KEY_UPDATE_LEAVE:
                              handleLeaveUpdate();
                              break;
                          case RequestCodes.RECEIVE_MESSAGE:
                              break;
                          case RequestCodes.LISTEN_PORT:
                              break;
                      } 
                    }
                } catch (IOException ex) {
                    Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        keyServerListener.start();
    }
    
    //first packet will tell of type of message -- TEXT/PROTOCOL/FILE?
    private void listenToMulticast(final int port) {
        Thread groupListener = new Thread(new Runnable() {
            @Override
            public void run() {
                try (MulticastSocket multiSocket = new MulticastSocket(port)) {
                    multiSocket.joinGroup(multicastAddress);
                    byte[] buffer = new byte[RequestCodes.BUFFER_SIZE];
                    while (isConnected) {
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                        multiSocket.receive(packet);
                        byte code = buffer[0];              //first byte of packet contains type
                        System.out.println(code);
                        switch ((int)code) {
                            case RequestCodes.RECEIVE_MESSAGE:
                                readMessage(buffer);
                                break;
                            case RequestCodes.KEY_UPDATE_JOIN:
                                handleJoinUpdate();
                                return;
                            case RequestCodes.KEY_UPDATE_LEAVE:
                                handleLeaveUpdate();
                                return;
                        }
                    }                    
                } catch (IOException ex) {
                    Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
                } 
            }
        });
        groupListener.start();
    }
    
    private void handleJoinUpdate() {
        groupKey = Security.updateKey(groupKey);
    }
    
    private void handleLeaveUpdate() {
        
    }
    
    private void readMessage(byte[] buffer) {
        
    }
    
    public void setParentCode(int parentCode) {
        this.parentCode = parentCode;
    }
    
    public void setKey(SecretKey key) {
        this.key = key;
    }
    
    public UUID getId() {
        return memberID;
    }
    
    @Override
    public String toString() {
        return "ID: " + memberID.toString() + "  ParentCode: " + parentCode + "\n" + "GK - " + DatatypeConverter.printHexBinary(groupKey.getEncoded());
    }
}