package ckcs.classes;

import ckcs.interfaces.KeyServer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class GroupController implements KeyServer {
    
    //GK is stored as root of tree, gets GK by calling tree.getRootKey();
    //updates GK by calling tree.setRootKey(SecretKey key);
    private LogicalTree tree;
    private ArrayList<UUID> groupMembers;
    
    public static void main (String args[]) {
        test3();
    }
    
    private static void test3() {
        try {
            Runnable listener = new Runnable() {
                @Override
                public void run() {
                    try {
                        ServerSocket server = new ServerSocket(15000);
                        Socket soc = server.accept();
                        //assume connected to a member
                        DataInputStream in = new DataInputStream(soc.getInputStream());
                        DataOutputStream out = new DataOutputStream(soc.getOutputStream());
                        GroupMember member = new GroupMember();
                        SecretKey memberKey = Security.ECDHKeyAgreement(in, out);
                        System.out.println("KS: Shared Key - " + DatatypeConverter.printHexBinary(memberKey.getEncoded()));
                        UUID memberId = member.getId();
                        member.setKey(memberKey);
                        LogicalTree ta = new LogicalTree(2,3);
                        ta.add(memberId, memberKey);
                        //now send groupMember parentCode info and GK, both encrypted
                        BigInteger big = BigInteger.valueOf(ta.getParentCode(memberId));
                        byte[] encryptedParentCode = Security.AESEncrypt(memberKey, big.toByteArray());
                        System.out.println("KS: Decrypted ParentCode - " + DatatypeConverter.printHexBinary(big.toByteArray()));
                        out.writeInt(encryptedParentCode.length);
                        out.write(encryptedParentCode);
                        System.out.println("KS: Encrypted ParentCode - " + DatatypeConverter.printHexBinary(encryptedParentCode));
                        
                        SecretKey groupKey = Security.generateRandomKey();
                        ta.setRootKey(groupKey);
                        System.out.println("KS: ParentCode - " + ta.getRootCode());
                        System.out.println("KS: GroupKey - " + DatatypeConverter.printHexBinary(groupKey.getEncoded()));
                        byte[] encryptedGK = ta.encryptGKForMember(memberId);
                        out.writeInt(encryptedGK.length);
                        out.write(encryptedGK);
                        System.out.println("KS: Encrypted GroupKey - " + DatatypeConverter.printHexBinary(encryptedGK));
                    } catch (IOException | Exceptions.NoMemberException ex) {
                        Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            };
            Thread listen = new Thread(listener);
            listen.start();
            
            Socket sock = new Socket(InetAddress.getLocalHost(), 15000);
            DataInputStream in = new DataInputStream(sock.getInputStream());
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());
            SecretKey key = Security.ECDHKeyAgreement(in, out);
            System.out.println("MB: Shared Key - " + DatatypeConverter.printHexBinary(key.getEncoded()));
            
            int length = in.readInt();
            byte[] received = new byte[length];
            in.read(received);
            System.out.println("MB: Encrypted ParentCode - " + DatatypeConverter.printHexBinary(received));
            byte[] decryptedParentCode = Security.AESDecrypt(key, received);
            System.out.println("MB: Decrypted ParentCode - " + DatatypeConverter.printHexBinary(decryptedParentCode));
            int parentCode = new BigInteger(decryptedParentCode).intValue();
            System.out.println("MB: ParentCode - " + parentCode);
            
            length = in.readInt();
            received = new byte[length];
            in.read(received);
            System.out.println("MB: Encrypted GroupKey - " + DatatypeConverter.printHexBinary(received));
            byte[] groupKey = Security.AESDecrypt(key, received);
            System.out.println("MB: GroupKey - " + DatatypeConverter.printHexBinary(groupKey));
            
        } catch (UnknownHostException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    private static void test2() {
            try {
            Runnable serv = new Runnable() {
                @Override
                public void run() {
                    try {
                        ServerSocket server = new ServerSocket(15000);
                        Socket accepted = server.accept();
                        DataInputStream userBin = new DataInputStream(accepted.getInputStream());
                        DataOutputStream userBout = new DataOutputStream(accepted.getOutputStream());
                        SecretKey key = Security.ECDHKeyAgreement(userBin, userBout);
                        System.out.println("KS: " + DatatypeConverter.printHexBinary(key.getEncoded()));
                        key = Security.updateKey(key);
                        System.out.println("KS: " + DatatypeConverter.printHexBinary(key.getEncoded()));
                        
                        
                    } catch (IOException ex) {
                        Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            };
            Thread ser = new Thread(serv);
            ser.start();
            
            Socket soc = new Socket(InetAddress.getLocalHost(), 15000);
            DataInputStream userAin = new DataInputStream(soc.getInputStream());
            DataOutputStream userAout = new DataOutputStream(soc.getOutputStream());
            SecretKey key = Security.ECDHKeyAgreement(userAin, userAout);
            System.out.println("MB: " + DatatypeConverter.printHexBinary(key.getEncoded()));
            key = Security.updateKey(key);
            System.out.println("MB: " + DatatypeConverter.printHexBinary(key.getEncoded()));
            SecretKey middleKey = Security.middleKeyCalculation(key, 12);
            System.out.println("Test Middle Key Calculation : " + DatatypeConverter.printHexBinary(middleKey.getEncoded()));
            SecretKey middleKey2 = Security.middleKeyCalculation(key, 10);
            System.out.println("Test Middle Key Calculation : " + DatatypeConverter.printHexBinary(middleKey2.getEncoded()));
        } catch (IOException ex) {
            Logger.getLogger(GroupController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private static void test() {
        GroupController KS = new GroupController();
        for (int i = 0; i < 8; i++) {
            KS.acceptJoinRequest();
        }
        System.out.println("rootCode: " + KS.tree.getRootCode());
        for (UUID id : KS.groupMembers) {
            GroupMember member = new GroupMember(id);
            member.setParentCode(KS.tree.getParentCode(id));
            System.out.println(member.toString());
            ArrayList<Integer> path = KS.tree.pathToRoot(id);
            System.out.println("Path to root: " + path);
        }
        
        GroupMember mbr = new GroupMember(KS.groupMembers.get(2));
        mbr.setParentCode(KS.tree.getParentCode(mbr.getId()));
        System.out.println("\nRemoving member: \n" + mbr.toString() + "\n");
        KS.removeGroupMember(mbr.getId());        
        for (UUID id : KS.groupMembers) {
            GroupMember member = new GroupMember(id);
            member.setParentCode(KS.tree.getParentCode(id));
            System.out.println(member.toString());   
            ArrayList<Integer> path = KS.tree.pathToRoot(id);
            System.out.println("Path to root: " + path);
        }
        
        mbr = new GroupMember(KS.groupMembers.get(2));
        mbr.setParentCode(KS.tree.getParentCode(mbr.getId()));
        System.out.println("\nRemoving member: \n" + mbr.toString() + "\n");
        KS.removeGroupMember(mbr.getId());      
        for (UUID id : KS.groupMembers) {
            GroupMember member = new GroupMember(id);
            member.setParentCode(KS.tree.getParentCode(id));
            System.out.println(member.toString());
            ArrayList<Integer> path = KS.tree.pathToRoot(id);
            System.out.println("Path to root: " + path);
        }
    }
    
    public GroupController() {
        tree = new LogicalTree(2, 3);
        groupMembers = new ArrayList<>();
    }

    @Override
    public void acceptJoinRequest() {
        GroupMember member = new GroupMember();
        groupMembers.add(member.getId());
        SecretKey key = Security.generateRandomKey();       //This should involve some ECDH key agreement
        tree.add(member.getId(), key);                  //or DH key agreement so no secret key is transfered over network
        member.setKey(key); 
    }

    @Override
    public void removeGroupMember(UUID memberId) {
        try {
            tree.remove(memberId);
            groupMembers.remove(memberId);
        } catch (Exceptions.NoMemberException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public void updateLogicalTree() {
    }
    
    //start thread that waits for ~10 seconds to accept any more incoming joinRequests
    @Override
    public void simultaneousJoin() {
    }

    //start thread waits for ~10 seconds to accept any more incoming leaveRequests
    @Override
    public void simultaneousLeave() {
    }  
    
    //randomly generate new GK
    private void updateKeyOnLeave() {
        tree.setRootKey(Security.updateKey(tree.getRootKey()));
    }
    
    //new GK is hash of old GK
    private void updateKeyOnJoin() {
    } 
}