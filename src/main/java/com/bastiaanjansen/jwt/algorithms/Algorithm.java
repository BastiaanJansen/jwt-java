package com.bastiaanjansen.jwt.algorithms;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public abstract class Algorithm implements AlgorithmVerifier, AlgorithmSigner {

    protected final String name;
    protected final String jcaName;

    public Algorithm(String name, String jcaName) {
        this.name = name;
        this.jcaName = jcaName;
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

    public String getName() {
        return name;
    }

    public String getJcaName() {
        return jcaName;
    }
}
