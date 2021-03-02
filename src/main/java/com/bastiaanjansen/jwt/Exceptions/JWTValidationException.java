package com.bastiaanjansen.jwt.Exceptions;

public class JWTValidationException extends JWTException {

    public JWTValidationException() {}

    public JWTValidationException(String message) {
        super(message);
    }
}
