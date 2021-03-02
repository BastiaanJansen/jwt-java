package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

public interface JWTVerifier {
    void verify(JWT jwt) throws JWTValidationException;
}
