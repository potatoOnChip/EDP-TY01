package ckcs.classes;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Security {

    public static byte[] hashFunction(final byte[] input) {
        //returns a 256-bit hash using SHA-256 algo
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static SecretKey ECDHKeyAgreement(final DataInputStream in, final DataOutputStream out) {
            //is a BLOCKING function, two users must both confirm to begin before calling this function
            //must be called on both ends after confirmations received
            //include some sort of authentication between users, such as ID, Nonces, Certificates? -- prevent man-in-the-middle/replays
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
            keyPairGen.initialize(256);
            KeyPair keyPair = keyPairGen.genKeyPair();
            byte[] ourPubKeyBytes = keyPair.getPublic().getEncoded();
            out.write(ourPubKeyBytes);
            
            byte[] otherPubKeyBytes = new byte[91];    //PUKey exact size is 91 bytes
            in.readFully(otherPubKeyBytes);    //read bytes of other users public key -- BLOCKING
            PublicKey otherPubKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(otherPubKeyBytes));
            
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(otherPubKey, true);
            byte[] sharedKeyBytes = keyAgree.generateSecret();
            
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            List<ByteBuffer> pubKeyBytes = Arrays.asList(ByteBuffer.wrap(ourPubKeyBytes), ByteBuffer.wrap(otherPubKeyBytes));
            Collections.sort(pubKeyBytes);
            md.update(sharedKeyBytes);
            md.update(pubKeyBytes.get(0));
            md.update(pubKeyBytes.get(1));
            byte[] secretKeyBytes = md.digest();
            
            return (SecretKey) new SecretKeySpec(secretKeyBytes, "AES");
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] AESDecrypt(final SecretKey key, final byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] AESEncrypt(final SecretKey key, final byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static SecretKey generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Security.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }   
    
    //update key for JOINS
    public static SecretKey updateKey(final SecretKey key) {
        //returns new 256-bit key value using hash of inputted key
        byte[] keyHash = hashFunction(key.getEncoded());
        return (SecretKey) new SecretKeySpec(keyHash, "AES");
    }
    
    public static void deleteKey() {
        
    }

    public static SecretKey middleKeyCalculation(final SecretKey key, final int nodeNumber) {
        byte[] keyBytes = key.getEncoded();
        for(int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte)(keyBytes[i] ^ (byte)nodeNumber);
        }
        return (SecretKey) new SecretKeySpec(keyBytes, "AES");
    }
}