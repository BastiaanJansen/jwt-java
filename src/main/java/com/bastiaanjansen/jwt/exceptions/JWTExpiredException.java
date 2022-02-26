package com.bastiaanjansen.jwt.exceptions;

public class JWTExpiredException extends JWTValidationException {
    public JWTExpiredException() {}

    public JWTExpiredException(String message) {
        super(message);
    }
}
