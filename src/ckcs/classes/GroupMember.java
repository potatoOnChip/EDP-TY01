package ckcs.classes;

import ckcs.interfaces.RequestCodes;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class GroupMember {
    
    final private UUID memberID; //randomly assigned
    private UUID serverID;
    private SecretKey key; //Group Controller key exchange 
    private SecretKey groupKey;
    private int parentCode; //Should be obtained from GroupController via LogicalTree
    private int globalPort; //the port multicast group globally sends too
    private InetAddress multicastAddress;
    
    
    public GroupMember() {
        this(UUID.randomUUID());              
    }
    
    public GroupMember(UUID Id) {
        this.memberID = Id;
    }

    public void requestJoin(final InetAddress address, final int portNumber) {
        try {
            Socket socket = new Socket(address, portNumber);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            
            out.writeInt(RequestCodes.REQUEST_JOIN);
            String message = in.readUTF();
            String parts[] = message.split("::");
            serverID = UUID.fromString(parts[0]);
            int N1Received = Integer.parseInt(parts[1]);
            
            int N2 = (int)(1000 * Math.random() * Math.random());
            message = "" + N1Received + "::" + memberID.toString() + "::" + N2;
            out.writeUTF(message);
            this.key = Security.ECDHKeyAgreement(in, out);
            
            int length = in.readInt();
            byte[] received = new byte[length];
            in.readFully(received);
            message = new String(Security.AESDecrypt(key, received), StandardCharsets.UTF_8);
            parts = message.split("::");
            int N2Received = Integer.parseInt(parts[0]);
            UUID memID = UUID.fromString(parts[1]);
            if (N2Received != N2 || !memID.equals(memberID)) {
                System.out.println("Connection Failed -- Back Out");
                in.close(); out.close(); socket.close();
                return;
            }
            
            length = in.readInt();
            received = new byte[length];
            in.read(received);
            message = new String(Security.AESDecrypt(key, received), StandardCharsets.UTF_8);
            parts = message.split("::");
            parentCode = Integer.parseInt(parts[0]);
            multicastAddress = InetAddress.getByName(parts[1]);
            globalPort = Integer.parseInt(parts[3]);
            
            length = in.readInt();
            received = new byte[length];
            in.read(received);
            groupKey = new SecretKeySpec(received, "AES");
            System.out.println("Connection Successful! Added to group");
            in.close();
            out.close();
            socket.close();
        } catch (IOException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    public void requestLeave(final InetAddress address, final int portNumber) {
        try {
            Socket socket = new Socket(address, portNumber);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            
            out.writeInt(RequestCodes.REQUEST_LEAVE);
            String message = in.readUTF();
            String parts[] = message.split("::");
            UUID servID = UUID.fromString(parts[0]);
            if (servID.equals(serverID)) {
                System.out.println("Connection Failed -- Backout");
                in.close();
                out.close();
                socket.close();
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
            in.close();
            out.close();
            socket.close();            
        } catch (IOException ex) {
            Logger.getLogger(GroupMember.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

  
    public void sendMessage() {
    }

    public void startListening() {
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
        return "ID: " + memberID.toString() + "  ParentCode: " + parentCode;
    }
}