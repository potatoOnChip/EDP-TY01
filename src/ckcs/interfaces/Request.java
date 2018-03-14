package ckcs.interfaces;

public interface Request {
    final static int JOIN = 1;
    final static int LEAVE = 2;
    final static int SEND_MESSAGE = 4;
    final static int ERROR = 8;
    
    final static int BUFFER_SIZE = 1024;
}
