package ckcs.classes;

import ckcs.interfaces.KeyServer;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.UUID;
import javax.crypto.SecretKey;

public class GroupController implements KeyServer {
    
    //GK is stored as root of tree, gets GK by calling tree.getRootKey();
    //updates GK by calling tree.setRootKey(SecretKey key);
    private LogicalTree tree;
    private ArrayList<UUID> groupMembers;
    
    public static void main(String[] args) {
        GroupController f = new GroupController();
        
        for(int i = 0; i < 27; i++) {
            f.acceptJoinRequest();
        }
        
        for (UUID memb : f.groupMembers) {
            System.out.println("ID: " + memb + " ParentCode: " + f.tree.getParentCode(memb));
        }
        
    }
    
    public GroupController() {
        tree = new LogicalTree(3, 3);
        groupMembers = new ArrayList<>();
    }

    public void startListening(final int portNumber) {
        while (true) {
            listenToPort(portNumber);
        }
    }
    
    //to constantly listen to requests for n active members; multihandle requests
    private void listenToPort(final int portNumber) {
        
    }
    
    @Override
    public void acceptJoinRequest() {
        GroupMember member = new GroupMember();
        groupMembers.add(member.getId());
        SecretKey key = Security.generateRandomKey();       //This should involve some ECDH key agreement
        tree.add(member.getId(), key);                  //or DH key agreement so no secret key is transfered over network
        member.setKey(key); 
        System.out.println("member number: " + member.getId() + " code: " + tree.getParentCode(member.getId()));
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
        tree.setGroupKey(Security.updateKey(tree.getGroupKey()));
    }
    
    //new GK is hash of old GK
    private void updateKeyOnJoin() {
    } 
}