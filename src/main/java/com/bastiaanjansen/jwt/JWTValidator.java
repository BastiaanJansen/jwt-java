package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

public interface JWTValidator {
    void validate(JWT jwt) throws JWTValidationException;
}
