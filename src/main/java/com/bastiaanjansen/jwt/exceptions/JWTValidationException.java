package com.bastiaanjansen.jwt.exceptions;

public class JWTValidationException extends JWTException {

    public JWTValidationException() {}

    public JWTValidationException(String message) {
        super(message);
    }
}
