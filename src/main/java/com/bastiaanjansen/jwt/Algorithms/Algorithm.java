package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.SignException;

import java.nio.charset.StandardCharsets;

public abstract class Algorithm {

    protected final String name;
    protected final String description;

    Algorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public static Algorithm HMAC256(String secret) {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret.getBytes(StandardCharsets.UTF_8));
    }

    public static Algorithm HMAC384(String secret) {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret.getBytes(StandardCharsets.UTF_8));
    }

    public static Algorithm HMAC512(String secret) {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret.getBytes(StandardCharsets.UTF_8));
    }

    public abstract byte[] sign(String data) throws SignException;

    public abstract byte[] sign(byte[] data) throws SignException;

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }
}
