package com.bastiaanjansen.jwt.Exceptions;

public class JWTDecodeException extends JWTException {

    public JWTDecodeException() {}

    public JWTDecodeException(String message) {
        super(message);
    }
}
