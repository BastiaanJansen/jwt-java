package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.SignException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACAlgorithm extends Algorithm {

    private final byte[] secret;

    HMACAlgorithm(String name, String description, byte[] secret) {
        super(name, description);
        this.secret = secret;
    }

    @Override
    public byte[] sign(String data) throws SignException {
        return sign(data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] sign(byte[] data) throws SignException {
        try {
            Mac HMAC = Mac.getInstance(description);

            SecretKeySpec secretKey = new SecretKeySpec(secret, description);
            HMAC.init(secretKey);

            return HMAC.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SignException(e.getMessage());
        }
    }
}
