package com.bastiaanjansen.jwt.Exceptions;

public class JWTDecodeException extends Exception {

    public JWTDecodeException() {}

    public JWTDecodeException(String message) {
        super(message);
    }
}
