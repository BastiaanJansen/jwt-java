package com.bastiaanjansen.jwt.Exceptions;

public class SignException extends JWTException {

    public SignException() {}

    public SignException(String message) {
        super(message);
    }

}
