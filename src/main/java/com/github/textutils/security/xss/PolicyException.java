package com.github.textutils.security.xss;

public class PolicyException extends Exception {

    private static final long serialVersionUID = -2045960001387814125L;

    public PolicyException(Exception e){
        super(e);
    }

    public PolicyException(String string){
        super(string);
    }
}
