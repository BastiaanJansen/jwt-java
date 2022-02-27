package com.bastiaanjansen.jwt.exceptions;

public class InvalidSignatureException extends JWTValidationException {
    public InvalidSignatureException() {}

    public InvalidSignatureException(String message) {
        super(message);
    }
}
