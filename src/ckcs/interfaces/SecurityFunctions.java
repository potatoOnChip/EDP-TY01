package ckcs.interfaces;

//for a static class that incorprates all the security funcitons

import javax.crypto.SecretKey;

//required of this GKMP ( CKCS )
//hash function, decryption/encryption, Key Agreement (DHellman or ECDH)
//generation of keys etc.
public interface SecurityFunctions {
    
    public byte[] hashFunction(final byte[] input);
    public String ECDHKeyAgreement();
    public byte[] decrypt(final SecretKey key, final byte[] input);
    public byte[] encrypt(final SecretKey key, final byte[] input);
    public SecretKey generateRandomKey();
    public SecretKey updateKey(final SecretKey key);
    public String middleKeyCalculation();
}
