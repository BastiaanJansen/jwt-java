package com.bastiaanjansen.jwt.exceptions;

public class MissingClaimException extends JWTValidationException {
    public MissingClaimException() {}

    public MissingClaimException(String message) {
        super(message);
    }
}
