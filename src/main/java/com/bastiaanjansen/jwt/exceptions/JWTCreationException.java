package com.bastiaanjansen.jwt.exceptions;

public class JWTCreationException extends JWTException {

    public JWTCreationException() {}

    public JWTCreationException(String message) {
        super(message);
    }
}
