package com.bastiaanjansen.jwt.Exceptions;

public class JWTExpiredException extends JWTValidationException {
    public JWTExpiredException() {}

    public JWTExpiredException(String message) {
        super(message);
    }
}
