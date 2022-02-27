package com.bastiaanjansen.jwt.algorithms;

import com.bastiaanjansen.jwt.exceptions.JWTSignException;

import java.nio.charset.StandardCharsets;

public interface AlgorithmSigner {
    default byte[] sign(String data) throws JWTSignException {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        return sign(bytes);
    }

    byte[] sign(byte[] data) throws JWTSignException;
}
