package com.bastiaanjansen.jwt.algorithms;

import com.bastiaanjansen.jwt.exceptions.JWTSignException;
import com.bastiaanjansen.jwt.exceptions.JWTValidationException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMACAlgorithm extends Algorithm {

    private final SecretKey key;

    protected HMACAlgorithm(String name, SecretKey key, int minKeyLength) {
        super(name, key.getAlgorithm(), key, minKeyLength);
        this.key = key;
    }

    @Override
    public byte[] sign(byte[] data) throws JWTSignException {
        try {
            Mac mac = Mac.getInstance(jcaName);

            mac.init(key);

            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new JWTSignException(e.getMessage());
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] expected) throws JWTValidationException {
        try {
            byte[] signed = sign(data);

            return Arrays.equals(signed, expected);
        } catch (JWTSignException e) {
            throw new JWTValidationException(e.getMessage());
        }
    }
}
