package ckcs.classes;

import ckcs.interfaces.Member;
import java.util.ArrayList;
import java.util.UUID;
import javax.crypto.SecretKey;

public class GroupMember implements Member {
    
    private UUID memberId; //randomly assigned
    private SecretKey key; //Group Controller key exchange 
    private int parentCode; //Should be obtained from GroupController via LogicalTree
    private int rootCode; //Obtained from GroupController
    private ArrayList<SecretKey> pathKeys; //Calculated using hash of GK XOR ParentCode :: would need to know root code
    
    public GroupMember() {
        this(UUID.randomUUID());              
    }
    
    public GroupMember(UUID Id) {
        this.memberId = Id;
    }

    @Override
    public void joinGroup() {
        
    }

    @Override
    public void leaveGroup() {
    }

  
    @Override
    public void sendMessage() {
    }

    //for purpose of receiving messages, start a listener thread
    @Override
    public void startListening() {
    }
    
    public void setParentCode(int parentCode) {
        this.parentCode = parentCode;
    }
    
    public void setKey(SecretKey key) {
        this.key = key;
    }
    
    public UUID getId() {
        return memberId;
    }
    
    @Override
    public String toString() {
        return "ID: " + memberId.toString() + "  ParentCode: " + parentCode;
    }
}