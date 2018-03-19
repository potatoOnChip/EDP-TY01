package ckcs.classes;

import static java.lang.Thread.sleep;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author abika
 */
public class MainClass {
    static ArrayList<GroupMember> members = new ArrayList<>();
    static InetAddress address;
    static GroupController keyServer;
    
    public static void main(String[] args) throws UnknownHostException, InterruptedException {
        keyServer = new GroupController(InetAddress.getByName("239.255.255.250"));
        address = InetAddress.getLocalHost();
        
        Thread th = new Thread(new Runnable() {
            @Override
            public void run() {
                keyServer.startListening(15000);
                keyServer.setMulticastPort(10000);
            }
        });
        th.start();
        System.out.println(keyServer.toString());
        
        for (int i = 0; i < 8; i++) {
            addMember(10000 + i);
        }
        
        for (int i = 0; i < 4; i++) {
            removeMember(i);
        }
    }
    
    private static void printMembers() throws InterruptedException {
        sleep(100);
        for (GroupMember mem : members) 
            System.out.println(mem.toString());
    }
    
    private static void addMember(int port) throws InterruptedException {
        GroupMember member = new GroupMember(port);
        member.requestJoin(address, 15000);
        members.add(member);
        printMembers();
        System.out.println(keyServer.toString());
    }
    
    private static void removeMember(int index) throws InterruptedException {
        GroupMember member = members.get(index);
        System.out.println("Removing member: " + member.getId().toString());
        member.requestLeave(address, 15000);
        members.remove(index);
        printMembers();
        System.out.println(keyServer.toString());
    }
}
