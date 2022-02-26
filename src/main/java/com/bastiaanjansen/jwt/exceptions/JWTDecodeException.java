package com.bastiaanjansen.jwt.exceptions;

public class JWTDecodeException extends JWTException {

    public JWTDecodeException() {}

    public JWTDecodeException(String message) {
        super(message);
    }
}
