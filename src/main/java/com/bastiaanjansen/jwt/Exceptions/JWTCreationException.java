package com.bastiaanjansen.jwt.Exceptions;

public class JWTCreationException extends Exception {

    public JWTCreationException() {}

    public JWTCreationException(String message) {
        super(message);
    }
}
