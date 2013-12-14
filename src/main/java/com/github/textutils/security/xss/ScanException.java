package com.github.textutils.security.xss;

public class ScanException extends RuntimeException {

    private static final long serialVersionUID = -8204412394195926823L;

    public ScanException(Exception e){
        super(e);
    }

    public ScanException(String string){
        super(string);
    }
}
