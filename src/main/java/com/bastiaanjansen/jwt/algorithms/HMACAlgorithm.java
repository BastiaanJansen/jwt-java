package com.bastiaanjansen.jwt.algorithms;

import com.bastiaanjansen.jwt.exceptions.JWTSignException;
import com.bastiaanjansen.jwt.exceptions.JWTValidationException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMACAlgorithm extends Algorithm {

    private final byte[] secret;

    HMACAlgorithm(String name, String description, byte[] secret) {
        super(name, description);
        this.secret = secret;
    }

    @Override
    public byte[] sign(String data) throws JWTSignException {
        return sign(data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] sign(byte[] data) throws JWTSignException {
        try {
            Mac mac = Mac.getInstance(description);

            SecretKeySpec secretKey = new SecretKeySpec(secret, description);
            mac.init(secretKey);

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
