package com.bastiaanjansen.jwt.algorithms;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;

public abstract class Algorithm implements AlgorithmVerifier, AlgorithmSigner {

    protected final String name;
    protected final String jcaName;
    protected final int minKeyLength;
    protected final Key key;

    protected Algorithm(String name, String jcaName, Key key, int minKeyLength) {
        this.name = name;
        this.jcaName = jcaName;
        this.key = key;
        this.minKeyLength = minKeyLength;
    }

    public static Algorithm HMAC256(byte[] secret) {
        SecretKey key = new SecretKeySpec(secret, "HmacSHA256");
        return new HMACAlgorithm("HS256", key, 256);
    }

    public static Algorithm HMAC384(byte[] secret) {
        SecretKey key = new SecretKeySpec(secret, "HmacSHA384");
        return new HMACAlgorithm("HS384", key, 384);
    }

    public static Algorithm HMAC512(byte[] secret) {
        SecretKey key = new SecretKeySpec(secret, "HmacSHA512");
        return new HMACAlgorithm("HS512", key, 512);
    }

    public static Algorithm RSA256(KeyPair keyPair) {
        return new RSAAlgorithm("RS256", "SHA256withRSA", keyPair, 2048);
    }

    public static Algorithm RSA384(KeyPair keyPair) {
        return new RSAAlgorithm("RS384", "SHA384withRSA", keyPair, 3072);
    }

    public static Algorithm RSA512(KeyPair keyPair) {
        return new RSAAlgorithm("RS512", "SHA512withRSA", keyPair, 4096);
    }

    public boolean isKeyLengthValid() {
        int bits = key.getEncoded().length * Byte.SIZE;
        return bits >= minKeyLength;
    }

    public String getName() {
        return name;
    }

    public String getJcaName() {
        return jcaName;
    }
}
