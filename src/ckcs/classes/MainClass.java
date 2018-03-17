package ckcs.classes;

import static java.lang.Thread.sleep;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 *
 * @author abika
 */
public class MainClass {
    public static void main(String[] args) throws UnknownHostException, InterruptedException {
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
        GroupMember member1 = new GroupMember(10000);
        member1.requestJoin(InetAddress.getLocalHost(), 15000);
        System.out.println(member1.toString());
        System.out.println(keyServer.toString());
        
        GroupMember member2 = new GroupMember(10001);
        member2.requestJoin(InetAddress.getLocalHost(), 15000);
        System.out.println(member1.toString());
        System.out.println(member2.toString());
        System.out.println(keyServer.toString());
        
        GroupMember member3 = new GroupMember(10002);
        member3.requestJoin(InetAddress.getLocalHost(), 15000);
        sleep(100);
        System.out.println(member1.toString());
        System.out.println(member2.toString());
        System.out.println(member3.toString());
        System.out.println(keyServer.toString());
        
        GroupMember member4 = new GroupMember(10003);
        member4.requestJoin(InetAddress.getLocalHost(), 15000);
        sleep(100);
        System.out.println(member1.toString());
        System.out.println(member2.toString());
        System.out.println(member3.toString());
        System.out.println(member4.toString());
        System.out.println(keyServer.toString());
    }
}
