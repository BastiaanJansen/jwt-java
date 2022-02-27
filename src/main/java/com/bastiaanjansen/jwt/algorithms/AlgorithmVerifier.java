package com.bastiaanjansen.jwt.algorithms;

import com.bastiaanjansen.jwt.exceptions.JWTValidationException;

public interface AlgorithmVerifier {
    boolean verify(byte[] data, byte[] expected) throws JWTValidationException;
}
