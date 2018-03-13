package ckcs.classes;

public class Exceptions {
    
    public static class NoMemberException extends Exception {
        public NoMemberException(String message) {
            super(message);
        }
    }
}
