package ckcs.classes;

import ckcs.classes.Exceptions.NoMemberException;
import ckcs.interfaces.Node;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.ListIterator;
import java.util.TreeMap;
import java.util.UUID;
import javax.crypto.SecretKey;

//tree constructed as a binary tree, strictly to hold data for KeyServer
//and some minimum data manipulation 
//maybe enclose all key info and key handling in this class
public class LogicalTree {
    
    private TreeMap<Integer, MiddleNode> middleNodes; //red-black based; ordered mapping via keys (node codes)
    private TreeMap<Integer, ArrayList<Integer>> codeValuesTaken;
    private HashMap<UUID, LeafNode> leafNodes; //UUID = groupMember ID
    private MiddleNode rootNode;    //holds group key
    private int maxChildren;    // max number of children for each node
    private int numberOfCodeDigits; // for rootNode; e.g. 20143 = 5
    private ListIterator iteratorChild;
    private ListIterator iteratorMiddle;
    
    //generates new logical tree for KeyServer to maintain
    //starts with root node as group key
    public LogicalTree(int maxChildren, int numberOfCodeDigits) {
        this.middleNodes = new TreeMap<>(); 
        this.codeValuesTaken = new TreeMap<>();
        this.leafNodes = new HashMap<>(); 
        this.maxChildren = maxChildren;
        this.numberOfCodeDigits = numberOfCodeDigits;
        this.rootNode = new MiddleNode();
        
        middleNodes.put(rootNode.nodeCode, rootNode);
        ArrayList<Integer> keyList = new ArrayList<>(middleNodes.keySet());
        iteratorChild = keyList.listIterator();
        iteratorMiddle = keyList.listIterator();
    }
    
    //KeyServer requests to encrypt GK to send to a member
    //search through leafNodes to find member, then work up path to root and 
    //encrypt GK with highest middleNode that is NOT exposed
    public byte[] encryptGKForMember(UUID memberId) throws NoMemberException {
        LeafNode member = leafNodes.get(memberId);
        if (member == null) 
            throw new NoMemberException("Given memberId does not match a registered member");
        
        SecretKey groupKey = rootNode.key;
        ArrayList<Integer> path = pathToRoot(member);
        ListIterator it = path.listIterator(path.size());
        while (it.hasPrevious()) {
            Integer nodeCode = (Integer)it.previous();
            MiddleNode middle = middleNodes.get(nodeCode);
            if (!middle.exposed) {
                SecretKey middleKey = Security.middleKeyCalculation(groupKey, middle.nodeCode);
                return Security.AESEncrypt(middleKey, groupKey.getEncoded());
            }
        }
        return Security.AESEncrypt(member.key, groupKey.getEncoded());
    }
    
    //remove a node from the tree
    //KeyServer handles the maintaince and updating of tree
    //LogicalTree doesn't know anything about it's shape/layout
    public void remove(UUID memberId) throws NoMemberException {
        //set necessary middle nodes to exposed when member is removed
        LeafNode member = leafNodes.get(memberId);
        if (member == null) {
            throw new Exceptions.NoMemberException("Given member does not exist in tree.");
        }
        MiddleNode parent = middleNodes.get(member.parentCode);
        if (parent.children.size() > 2) {
            leafNodes.remove(memberId);
            parent.children.remove(memberId);
            setExposed(pathToRoot(member));
        } else {
            int newParentCode = parent.parentCode;
            for (UUID Id : parent.children) {
                if (!Id.equals(memberId)) {
                    LeafNode sibling = leafNodes.get(Id);
                    sibling.parentCode = newParentCode;
                    setExposed(pathToRoot(sibling));
                    leafNodes.put(Id, sibling);      
                }
            }
            middleNodes.remove(parent.nodeCode);
            leafNodes.remove(memberId);
        }
    } 
    
    private void setExposed(ArrayList<Integer> exposedPath) {
        for (Integer nodeCode : exposedPath) {
            MiddleNode node = middleNodes.get(nodeCode);
            node.exposed = true;
            middleNodes.put(nodeCode, node);    //always must put node back into TreeMap to update stored value
        }
    }
    
    //for group controller to give group member their parentCode
    public Integer getParentCode(UUID memberId) {
        LeafNode child = leafNodes.get(memberId);
        return child.parentCode;
    }
    
    public Integer getRootCode() {
        return rootNode.nodeCode;
    }
    
    //firts iterates through iteratorChild -- which goes through each middleNode and adds new member only if 
    //that middleNode has space for children -- it's numberOfChildren < maxNumberOfChildren
    //if NO middleNode exists with space for children, iterate through MiddleNodes and replace a LEAFNODE with
    //a new MIDDLENODE and attach new member to that NEW MIDDLENODE
    //This ensures that ALL MIDDLENODES are full with children before deciding to replace a CHILD with a new MIDDLENODE 
    public void add(UUID memberId, SecretKey key) {
        updateChildIterator();
        while (iteratorChild.hasNext()) {
            int code = (Integer)iteratorChild.next();
            MiddleNode parent = middleNodes.get(code);
            if (addLeaf(parent, memberId, key)) {
                middleNodes.put(code, parent);
                return;
            }
        }
        setChildIterator(0);
        updateMiddleIterator();
        while(iteratorMiddle.hasNext()) {
            int code = (Integer)iteratorMiddle.next();
            MiddleNode parent = middleNodes.get(code);
            if (addMiddleAndLeaf(parent, memberId, key)) {
                middleNodes.put(code, parent);
                return;
            }
        }
    }
    
    private boolean addLeaf(MiddleNode parent, UUID memberId, SecretKey key) {
        if (parent.numberOfChildren < maxChildren) {
            LeafNode child = new LeafNode(parent.nodeCode, key);
            parent.children.add(memberId);
            parent.numberOfChildren++;
            leafNodes.put(memberId, child);
            iteratorChild.previous();
            return true;
        }
        return false;
    }
    
    //removes a child leaf, replaces it with a new middlenode, attaches removed child leaf to 
    //the new middlenode, then attaches new group member leaf node to new middlenode 
    private boolean addMiddleAndLeaf(MiddleNode parent, UUID memberId, SecretKey key) {
        ListIterator childIterator = parent.children.listIterator();
        if (childIterator.hasNext()) {
            UUID childOneId = (UUID)childIterator.next();
            LeafNode childOne = leafNodes.get(childOneId);
            parent.children.remove(childOneId);
            
            MiddleNode middleChild = new MiddleNode(parent.nodeCode);
            LeafNode child = new LeafNode(middleChild.nodeCode, key);
            middleChild.children.add(childOneId);
            middleChild.children.add(memberId);
            middleChild.numberOfChildren += 2;
            childOne.parentCode = middleChild.nodeCode;
            middleNodes.put(middleChild.nodeCode, middleChild);
            leafNodes.put(childOneId, childOne);
            leafNodes.put(memberId, child);
            iteratorMiddle.previous();
            return true;
        }
        return false;
    }
    
    public ArrayList<Integer> pathToRoot(UUID id) {
        ArrayList<Integer> path = new ArrayList<>();
        LeafNode leaf = leafNodes.get(id);
        int parentCode = leaf.parentCode;
        while (parentCode != rootNode.nodeCode) {
            path.add(parentCode);
            parentCode = removeDigit(parentCode);
        }
        return path;
    }
    
    private ArrayList<Integer> pathToRoot(LeafNode leaf) {
        ArrayList<Integer> path = new ArrayList<>();
        int parentCode = leaf.parentCode;
        while (parentCode != rootNode.nodeCode) {
            path.add(parentCode);
            parentCode = removeDigit(parentCode);
        }
        return path;
    }
    
    private int removeDigit(int parentCode) {
        String code = Integer.toString(parentCode);
        String nodeCode = code.substring(0, code.length() - 1);
        return Integer.parseInt(nodeCode);
    }
    
    private int addRandomDigit(Integer parentCode) {
        int digitSize = parentCode.toString().length() + 1;
        int recurse = 0;
        
        if (codeValuesTaken.get(digitSize) == null) {
            ArrayList<Integer> codes = new ArrayList<>();
            codeValuesTaken.put(digitSize, codes);
        }
        ArrayList<Integer> codes = codeValuesTaken.get(digitSize);
        Integer code = Integer.parseInt("" + parentCode + "" + (int)(10 * Math.random()));
        while (codes.contains(code)) {
            recurse++;
            code = Integer.parseInt("" + parentCode + "" + (int)(10 * Math.random()));
            if (recurse > 9) {
                TreeMap<Integer, MiddleNode> tempMiddles = new TreeMap<>();
                tempMiddles.putAll(middleNodes);
                middleNodes.clear();
                codeValuesTaken.clear();
                updateNodeCodes(rootNode, setRootCode(numberOfCodeDigits++), tempMiddles.values());
            }
        }
        codes.add(code);
        codeValuesTaken.put(digitSize, codes);
        return code;
    }
    
    private void setChildIterator(int position) {
        ArrayList<Integer> keyList = new ArrayList<>(middleNodes.keySet());
        iteratorChild = keyList.listIterator(position);
    }
    
    //purpose is to update iterator with new list of keys
    private void updateChildIterator() {
        int position = iteratorChild.nextIndex();
        setChildIterator(position);
    }
    
    //purpose is to reset iterator to beginning of new list
    private void updateMiddleIterator() {
        int position = iteratorMiddle.nextIndex();
        ArrayList<Integer> keyList = new ArrayList<>(middleNodes.keySet());
        iteratorMiddle = keyList.listIterator(position);
    }
    
    //
    private void updateNodeCodes(MiddleNode node, int newParentCode, Collection<MiddleNode> middles) {
        int parentCode = node.nodeCode;
        node.parentCode = newParentCode;
        node.nodeCode = addRandomDigit(newParentCode);
        
        for (MiddleNode middleNode : middles) {
            if (middleNode.parentCode == parentCode) {
                updateNodeCodes(middleNode, node.nodeCode, middles);
            }
        }
        middleNodes.put(node.nodeCode, node);
    }
    
    //for simultaneous join, root nodes become children for the new root node
    //NEEDS TO BE TESTEDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
    public void combineTrees(LogicalTree tree) {
        MiddleNode tempNode = new MiddleNode();
        if (rootNode.nodeCode > 10) {
            tempNode.nodeCode = removeDigit(rootNode.nodeCode);
            rootNode.parentCode = tempNode.nodeCode;  
            middleNodes.put(rootNode.nodeCode, rootNode);
            middleNodes.put(tempNode.nodeCode, tempNode);
            rootNode = tempNode;
            
            Collection<MiddleNode> middles = tree.middleNodes.values();
            updateNodeCodes(tree.rootNode, rootNode.nodeCode, middles);
        } else {
            //assign larger nodecode values to all of em and recall
            TreeMap<Integer, MiddleNode> tempMiddles = new TreeMap<>();
            tempMiddles.putAll(middleNodes);
            middleNodes.clear();
            updateNodeCodes(rootNode, setRootCode(numberOfCodeDigits++), tempMiddles.values());
            combineTrees(tree);
        }
    }
    
    public SecretKey getRootKey() {
        return rootNode.key;
    }
    
    public void setRootKey(SecretKey key) {
        rootNode.key = key;
    }
    
    public int setRootCode(int DigitLength) {
        int multiplier = (int)(Math.pow(10, DigitLength));
        int code = (int)(Math.pow(10, DigitLength) * Math.random());
        if (code / (multiplier / 10) < 1) 
            code *= 10;
        return code;
    }
    
    //middlenode, just need to hold key and nodeCode, maybe an identifier?
    private class MiddleNode implements Node {
        private SecretKey key;
        private int parentCode;
        private int nodeCode;
        private int numberOfChildren;
        private ArrayList<UUID> children;
        private boolean exposed;
              
        public MiddleNode(int parentCode) {
            this.parentCode = parentCode;
            this.children = new ArrayList<>();
            this.exposed = false;
            this.numberOfChildren = 0;
            
            this.nodeCode = addRandomDigit(parentCode);
        }
        
        //only for rootNode
        private MiddleNode() {
            this.parentCode = 0;
            this.numberOfChildren = 0;
            this.children = new ArrayList<>();
            this.exposed = false;
            this.nodeCode = setRootCode(numberOfCodeDigits);
        }
    }
    
    //leafNode, aka group members. Only need info that KeyServer needs
    //no need to have instance of every member (keep everything to a minimum)
    private class LeafNode implements Node {
        private final SecretKey key;
        private int parentCode;
        
        public LeafNode(int position, SecretKey key) {
            this.parentCode = position; 
            this.key = key;
        }
    }
}