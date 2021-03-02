package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.JWTSignException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;
import com.bastiaanjansen.jwt.JWT;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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

    public static Algorithm RSA256(KeyPair keyPair) {
        return new RSAAlgorithm("RS256", "SHA256withRSA", keyPair);
    }

    public static Algorithm RSA384(KeyPair keyPair) {
        return new RSAAlgorithm("RS384", "SHA384withRSA", keyPair);
    }

    public static Algorithm RSA512(KeyPair keyPair) {
        return new RSAAlgorithm("RS512", "SHA512withRSA", keyPair);
    }

    public abstract byte[] sign(String data) throws JWTSignException;

    public abstract byte[] sign(byte[] data) throws JWTSignException;

    public abstract boolean verify(byte[] data, String expected) throws JWTValidationException;

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }
}
