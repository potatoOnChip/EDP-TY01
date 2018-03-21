package ckcs.classes;

import ckcs.classes.Exceptions.NoMemberException;
import ckcs.interfaces.Node;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
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
    private MiddleNode rootNode;
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
        List<Integer> keyList = new ArrayList<>(middleNodes.keySet());
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
        
        ArrayList<Integer> path = pathToRoot(member);
        ListIterator it = path.listIterator(path.size());
        int level = 0;
        while (it.hasPrevious()) {
            Integer nodeCode = (Integer)it.previous();
            MiddleNode middle = middleNodes.get(nodeCode);
            level++;
            if (!middle.exposed) {
                byte[] temp = Security.AESEncrypt(middle.key, rootNode.key.getEncoded());
                byte[] encryptedGK = Arrays.copyOf(temp, temp.length + 1);
                encryptedGK[temp.length] = (byte)level;
                return encryptedGK;
            }
        }
        level++;
        byte[] temp = Security.AESEncrypt(member.key, rootNode.key.getEncoded());
        byte[] encryptedGK = Arrays.copyOf(temp, temp.length + 1);
        encryptedGK[temp.length] = (byte)level;
        return encryptedGK;
    }
    
    private void updateMiddleKeys() {
        for (MiddleNode middle : middleNodes.values()) {
            if (middle.nodeCode != rootNode.nodeCode)
                middle.key = Security.middleKeyCalculation(rootNode.key, middle.nodeCode);
        }
    }
    
    //remove a node from the tree
    //KeyServer handles the maintaince and updating of tree
    //LogicalTree doesn't know anything about it's shape/layout
    public synchronized void remove(UUID memberId) throws NoMemberException {
        //set necessary middle nodes to exposed when member is removed
        LeafNode member = leafNodes.get(memberId);
        if (member == null) {
            throw new Exceptions.NoMemberException("Given member does not exist in tree.");
        }
        MiddleNode parent = middleNodes.get(member.parentCode);
        parent.children.remove(memberId);
        parent.numberOfChildren--;
        setExposed(pathToRoot(member));
        middleNodes.put(parent.nodeCode, parent);
        if (parent.children.size() < 2) {
            MiddleNode middle = null;
            if (parent.children.isEmpty()) {
                int siblingDigitSize = Integer.toString(parent.nodeCode).length() + 1;
                for (Integer nodeCode : codeValuesTaken.get(siblingDigitSize)) {
                    if (middleNodes.get(nodeCode).parentCode == parent.nodeCode) {
                        middle = middleNodes.get(nodeCode);
                    }
                }
                if (middle != null) {
                    if (middle.children.isEmpty()) {
                        int childDigitSize = Integer.toString(middle.nodeCode).length() + 1;
                        ArrayList<Integer> children = new ArrayList<>();
                        children.addAll(codeValuesTaken.get(childDigitSize));
                        middleNodes.remove(middle.nodeCode, middle);
                        codeValuesTaken.get(siblingDigitSize).remove(Integer.valueOf(middle.nodeCode));
                        parent.numberOfChildren--;
                        MiddleNode parentsParent = middleNodes.get(parent.parentCode);
                        if (parentsParent != null && parentsParent.numberOfChildren == 1) {
                            middleNodes.remove(parent.nodeCode, parent);
                            int parentDigitSize = Integer.toString(parent.nodeCode).length();
                            codeValuesTaken.get(parentDigitSize).remove(Integer.valueOf(parent.nodeCode));
                            parentsParent.numberOfChildren--;
                            for (Integer nodeCode : children) {
                                if (middleNodes.get(nodeCode).parentCode == middle.nodeCode) {
                                    MiddleNode child = middleNodes.get(nodeCode);
                                    codeValuesTaken.get(childDigitSize).remove(nodeCode);
                                    updateNodeCodes(child, parent.parentCode, middleNodes.values());
                                    parentsParent.numberOfChildren++;
                                }
                            }
                        } else {
                            for (Integer nodeCode : children) {
                                if (middleNodes.get(nodeCode).parentCode == middle.nodeCode) {
                                    MiddleNode child = middleNodes.get(nodeCode);
                                    codeValuesTaken.get(childDigitSize).remove(nodeCode);
                                    updateNodeCodes(child, parent.nodeCode, middleNodes.values());
                                    parent.numberOfChildren++;
                                }
                            }                                                                                    
                        }
                    } else {
                        codeValuesTaken.get(siblingDigitSize).remove(Integer.valueOf(middle.nodeCode));
                        middleNodes.remove(middle.nodeCode);
                        parent.numberOfChildren--;
                        for (UUID Id : middle.children) {
                            LeafNode child = leafNodes.get(Id);
                            child.parentCode = parent.nodeCode;
                            child.isParentUpdated = true;
                            parent.children.add(Id);
                            parent.numberOfChildren++;
                            leafNodes.put(Id, child);
                        }    
                        middleNodes.put(parent.nodeCode, parent);   
                    }
                }
            } else {
                int newParentCode = parent.parentCode;
                if (newParentCode != 0) {
                    middle = middleNodes.get(newParentCode);
                    UUID siblingId = parent.children.get(0);
                    LeafNode sibling = leafNodes.get(siblingId);
                    int digitSize = Integer.toString(parent.nodeCode).length();
                    codeValuesTaken.get(digitSize).remove(Integer.valueOf(parent.nodeCode));
                    middleNodes.remove(parent.nodeCode);
                    middle.numberOfChildren--;
                    
                    middle.children.add(siblingId);
                    sibling.parentCode = newParentCode;
                    sibling.isParentUpdated = true;
                    middle.numberOfChildren++;
                    leafNodes.put(siblingId, sibling);
                    middleNodes.put(newParentCode, middle);   
                } else {
                    middleNodes.put(parent.nodeCode, parent);
                }
            }
        }
        leafNodes.remove(memberId);
        updateMiddleKeys();
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
    public synchronized void add(UUID memberId, SecretKey key) {
        resetChildIterator();
        while (iteratorChild.hasNext()) {
            int code = (Integer)iteratorChild.next();
            MiddleNode parent = middleNodes.get(code);
            if (addLeaf(parent, memberId, key)) {
                middleNodes.put(code, parent);
                return;
            }
        }
        resetMiddleIterator();
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
            childOne.isParentUpdated = true;
            middleNodes.put(middleChild.nodeCode, middleChild);
            leafNodes.put(childOneId, childOne);
            leafNodes.put(memberId, child);
            return true;
        }
        return false;
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
        
        if (codeValuesTaken.get(digitSize) == null) {
            ArrayList<Integer> codes = new ArrayList<>();
            codeValuesTaken.put(digitSize, codes);
        }
        ArrayList<Integer> codes = codeValuesTaken.get(digitSize);
        Integer code = Integer.parseInt("" + parentCode + "" + (int)(10 * Math.random()));
        while (codes.contains(code)) {
            code = Integer.parseInt("" + parentCode + "" + (int)(10 * Math.random()));
        }
        codes.add(code);
        codeValuesTaken.put(digitSize, codes);
        return code;
    }
    
    private void resetMiddleIterator() {
        List<Integer> keyList = new ArrayList<>(middleNodes.keySet());
        iteratorMiddle = keyList.listIterator(0);
    }
    
    private void resetChildIterator() {
        List<Integer> keyList = new ArrayList<>(middleNodes.keySet());
        iteratorChild = keyList.listIterator(0);
    }
    
    //to update the nodeCodes and parentNodeCodes of all middleNodes under parameter - node
    private void updateNodeCodes(MiddleNode node, int newParentCode, Collection<MiddleNode> middles) {
        int parentCode = node.nodeCode;        
        node.parentCode = newParentCode;
        node.nodeCode = addRandomDigit(newParentCode);
        Collection<MiddleNode> nodes = new ArrayList<>();
        nodes.addAll(middles);
        
        for (MiddleNode middleNode : nodes) {
            if (middleNode.parentCode == parentCode) {
                updateNodeCodes(middleNode, node.nodeCode, nodes);
            }
        }
        for (UUID childId : node.children) {
            LeafNode child = leafNodes.get(childId);
            child.parentCode = node.nodeCode;
            child.isParentUpdated = true;
            leafNodes.put(childId, child);
        }
        middleNodes.put(node.nodeCode, node);
    }
    
    //for simultaneous join, root nodes become children for the new root node
    //NEEDS TO BE TESTEDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
    public void combineTrees(LogicalTree tree) {
        MiddleNode newRootNode = new MiddleNode();
        if (rootNode.nodeCode > 10) {
            newRootNode.nodeCode = removeDigit(rootNode.nodeCode);
            rootNode.parentCode = newRootNode.nodeCode;  
            middleNodes.put(rootNode.nodeCode, rootNode);
            middleNodes.put(newRootNode.nodeCode, newRootNode);
            rootNode = newRootNode;
            
            Collection<MiddleNode> middles = tree.middleNodes.values();
            updateNodeCodes(tree.rootNode, rootNode.nodeCode, middles);
        } else {
            //assign larger nodecode values to all of em and recall
            TreeMap<Integer, MiddleNode> tempMiddles = new TreeMap<>();
            tempMiddles.putAll(middleNodes);
            middleNodes.clear();
            updateNodeCodes(rootNode, setRootCode(++numberOfCodeDigits), tempMiddles.values());
            combineTrees(tree);
        }
    }
    
    public SecretKey getGroupKey() {
        return this.rootNode.key;
    }
    
    public void setGroupKey(SecretKey key) {
        this.rootNode.key = key;
    }
    
    public int setRootCode(int DigitLength) {
        int multiplier = (int)(Math.pow(10, DigitLength));
        int code = (int)(Math.pow(10, DigitLength) * Math.random());
        if (code / (multiplier / 10) < 1) 
            code *= 10;
        return code;
    }
    
    //every new middle node add causes a groupmember to loose sync with their parentCode
    //this only needs to be called once every member LEAVE -- cause only then will the
    //members need the appropriate codes -- on JOIN they only update using hash ---
    public List<UUID> codesToUpdate() {
        List<UUID> nodes = new ArrayList<>();
        for (UUID memID : leafNodes.keySet()) {
            LeafNode node = leafNodes.get(memID);
            if (node.isParentUpdated)
                nodes.add(memID);
        }
        return nodes;
    }
    
    @Override
    public String toString() {
        return "members: " + leafNodes.values().size();
    }
    
    //middlenode, just need to hold key and nodeCode, maybe an identifier?
    private class MiddleNode implements Node {
        private int parentCode;
        private int nodeCode;
        private int numberOfChildren;
        private ArrayList<UUID> children;
        private SecretKey key;
        private boolean exposed;
              
        public MiddleNode(int parentCode) {
            this.parentCode = parentCode;
            this.children = new ArrayList<>();
            this.exposed = false;
            this.numberOfChildren = 0;
            
            this.nodeCode = addRandomDigit(parentCode);
        }
        
        //ONLY for rootNode
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
        private boolean isParentUpdated;
        
        public LeafNode(int position, SecretKey key) {
            this.parentCode = position; 
            this.key = key;
        }
    }
}