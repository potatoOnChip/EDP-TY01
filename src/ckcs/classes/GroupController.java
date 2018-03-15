package ckcs.classes;

import ckcs.interfaces.RequestCodes;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

//should manage a multicast group, tell every member who join the 'ip-address of multicast'
public class GroupController {
    
    //GK is stored as root of tree, gets GK by calling tree.getRootKey();
    //updates GK by calling tree.setRootKey(SecretKey key);
    private final LogicalTree tree;
    private final ArrayList<UUID> groupMembers;
    private final UUID serverID;
    private final InetAddress address;
    private final int port;
    
    public GroupController(InetAddress groupAddress, int portNumber) {
        tree = new LogicalTree(2, 3);
        groupMembers = new ArrayList<>();
        serverID = UUID.randomUUID();
        this.address = groupAddress; //multicast group address
        this.port = portNumber; //global port that all should listen to, changing port selects listening traffic
    }
    
    //start a serverSocket listening for connections -- this is BLOCKING, 
    //every accepted connection spawns a new thread to handle the accepted 
    //connections --- either JOIN/LEAVE/MESSAGE request
    public void startListening(final int portNumber) {
        try {        
            ServerSocket server = new ServerSocket();
            server.bind(new InetSocketAddress(portNumber));
            while (true) {
                Socket socket = server.accept();
                new RequestHandler(socket).start();
            }
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //multicast to group members that key must be updated via hash for JOIN
    public void addMember(UUID memberID, SecretKey key) {
        tree.add(memberID, key);
        groupMembers.add(memberID);
        updateKeyOnJoin();
        multicastKeyJoinUpdate();
    }
    
    private void multicastKeyJoinUpdate() {
        try {
            try (DatagramSocket socket = new DatagramSocket()) {
                BigInteger big = BigInteger.valueOf(RequestCodes.KEY_UPDATE_JOIN);
                byte[] buffer = big.toByteArray();
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, port);
                socket.send(packet);
            }
        } catch (SocketException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //need to handle redistribution of keys------------
    public void removeMember(UUID memberId) {
        try {
            tree.remove(memberId);
            groupMembers.remove(memberId);
            updateKeyOnLeave();
        } catch (Exceptions.NoMemberException e) {
            System.out.println(e.getMessage());
        }
    }

    public void updateLogicalTree() {
    }
        
    //randomly generate new GK
    private void updateKeyOnLeave() {
        tree.setGroupKey(Security.generateRandomKey());
    }
    
    //new GK is hash of old GK
    private void updateKeyOnJoin() {
        tree.setGroupKey(Security.updateKey(tree.getGroupKey()));
    } 
    
    private void handleJoin(final DataInputStream in, final DataOutputStream out) {
        try {
            int N1 = (int)(100 * Math.random() * Math.random());
            String message = serverID.toString() + "::" + N1;
            out.writeUTF(message);
            message = in.readUTF();
            String parts[] = message.split("::");
            int N1Received = Integer.parseInt(parts[0]);
            if (N1 != N1Received) {
                System.out.println("Connection Failed -- Back Out");
                return;
            }
            UUID memID = UUID.fromString(parts[1]);
            int N2Received = Integer.parseInt(parts[2]);
            SecretKey sharedKey = Security.ECDHKeyAgreement(in, out);
            
            message = "" + N2Received + "::" + memID.toString();
            byte[] encryptedMessage = Security.AESEncrypt(sharedKey, message.getBytes(StandardCharsets.UTF_8));
            int length = encryptedMessage.length;
            out.writeInt(length);
            out.write(encryptedMessage);
            
            addMember(memID, sharedKey);
            int parentCode = tree.getParentCode(memID);
            message = "" + parentCode + "::" + address.getHostAddress() + "::" + port;
            encryptedMessage = Security.AESEncrypt(sharedKey, message.getBytes(StandardCharsets.UTF_8));
            length = encryptedMessage.length;
            out.writeInt(length);
            out.write(encryptedMessage);
            
            length = in.readInt();
            byte[] received = new byte[length];
            in.readFully(received);
            message = new String(Security.AESDecrypt(sharedKey, received), StandardCharsets.UTF_8);
            int receivedCode = Integer.parseInt(message);
            if (parentCode != receivedCode) {
                System.out.println("Connection Failed -- Back Out");
                return;
            }
            
            encryptedMessage = Security.AESEncrypt(sharedKey, tree.getGroupKey().getEncoded());
            length = encryptedMessage.length;
            out.writeInt(length);
            out.write(encryptedMessage);
            System.out.println("Connection Succesfull! Member added");
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void handleLeave(final DataInputStream in, final DataOutputStream out) {
        try {
            int N1 = (int)(100 * Math.random() * Math.random());
            String message = "" + serverID.toString() + "::" + N1;
            out.writeUTF(message);
            
            message = in.readUTF();
            String parts[] = message.split("::");
            int N1Received = Integer.parseInt(parts[0]);
            if (N1 != N1Received) {
                System.out.println("Connection Failed -- Back Out");
                return;
            }
            UUID memID = UUID.fromString(parts[1]);
            int N2Received = Integer.parseInt(parts[2]);
            removeMember(memID);
            out.writeInt(N2Received);
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private class RequestHandler extends Thread {
        Socket socket;
        
        private RequestHandler(Socket clientSocket) {
            this.socket = clientSocket;
        }
        
        @Override
        public void run() {
            try {
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                int request = in.readInt();
                if (request == RequestCodes.REQUEST_JOIN) {
                    handleJoin(in, out);
                }
                else if (request == RequestCodes.REQUEST_LEAVE) {
                    handleLeave(in, out);
                }
                in.close();
                out.close();
                socket.close();
            } catch (IOException ex) {
                Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}