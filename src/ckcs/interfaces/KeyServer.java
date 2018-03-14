package ckcs.interfaces;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.UUID;

public interface KeyServer {
    
    public void acceptJoinRequest();
    public void removeGroupMember(UUID memberId);
    public void updateLogicalTree();
    public void simultaneousJoin();
    public void simultaneousLeave();
}
