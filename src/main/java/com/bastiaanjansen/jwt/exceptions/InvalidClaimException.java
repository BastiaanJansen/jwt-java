package com.bastiaanjansen.jwt.exceptions;

public class InvalidClaimException extends JWTValidationException {
    public InvalidClaimException() {}

    public InvalidClaimException(String message) {
        super(message);
    }
}
