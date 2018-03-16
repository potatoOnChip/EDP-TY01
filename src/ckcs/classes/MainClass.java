package ckcs.classes;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author abika
 */
public class MainClass {
    public static void main(String[] args) throws UnknownHostException {
        final GroupController keyServer = new GroupController(InetAddress.getByName("239.255.255.250"));
        
        Thread th = new Thread(new Runnable() {
            @Override
            public void run() {
                keyServer.startListening(15000);
                keyServer.setMulticastPort(10000);
            }
        });
        th.start();
        
        System.out.println(keyServer.toString());
        GroupMember member1 = new GroupMember();
        member1.requestJoin(InetAddress.getLocalHost(), 15000);
        System.out.println(member1.toString());
        System.out.println(keyServer.toString());
        
        GroupMember member2 = new GroupMember();
        member2.requestJoin(InetAddress.getLocalHost(), 15000);
        System.out.println(member1.toString());
        System.out.println(member2.toString());
        System.out.println(keyServer.toString());
        
        
    }
}
