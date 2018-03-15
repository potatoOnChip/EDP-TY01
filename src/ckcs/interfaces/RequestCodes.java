package ckcs.interfaces;

//maybe include certification to prevent man in the middle?
//have the keyServer send they're certificate to prove themselves,
//signed by a trusty CA -- keyServer's ID is signed, 
//member can decrypt with CA's public key, if the received keyServer ID
//matches the signed ID -- TRUST
//requires every member have access to CA's public key -- EXTRA
public interface RequestCodes {
    final static int REQUEST_JOIN = 1;
    //---------- REQUEST PROTOCOL ---------
    //member sends REQUEST_JOIN 
    //keyServer sends serverID + Nonce N1 
    //member sends Nonce N1 + memID + Nonce N2
    //keyServer and member start ECDH Key Agreement
    //keyServer encrypts sends Nonce N2 + memID
    //keyServer addsMember
    //keyServer encrypts sends parentCode + multiCast group address + port
    //member encrypts sends parentCode
    //keyServer encrypts sends updated GK to member
    
    final static int REQUEST_LEAVE = 2;
    //------------ REQUEST LEAVE -----------
    //member sends REQUEST_LEAVE
    //keyServer sends serverID + Nonce N1
    //member sends Nonce N1 + memID + Nonce N2
    //keyServer removes member
    //keyServer sends Nonce N2 as an ACK
    
    final static int KEY_UPDATE_JOIN = 4;
    //to multicast to all members to update ON MEMBER JOIN
    //hash update their group keys
    
    final static int KEY_UPDATE_LEAVE = 8;
    final static int SEND_MESSAGE = 16;
    final static int ERROR = 128;
    
    final static int BUFFER_SIZE = 2048;
}
