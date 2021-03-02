package com.bastiaanjansen.jwt.Exceptions;

public class JWTCreationException extends JWTException {

    public JWTCreationException() {}

    public JWTCreationException(String message) {
        super(message);
    }
}
