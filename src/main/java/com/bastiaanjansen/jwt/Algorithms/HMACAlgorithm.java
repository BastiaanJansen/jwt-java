package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.JWTSignException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;
import com.bastiaanjansen.jwt.JWT;
import com.bastiaanjansen.jwt.Utils.Base64Utils;

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
    public byte[] sign(String data) throws JWTSignException {
        return sign(data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] sign(byte[] data) throws JWTSignException {
        try {
            Mac HMAC = Mac.getInstance(description);

            SecretKeySpec secretKey = new SecretKeySpec(secret, description);
            HMAC.init(secretKey);

            return HMAC.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new JWTSignException(e.getMessage());
        }
    }

    @Override
    public boolean verify(byte[] data, String expected) throws JWTValidationException {
        try {
            byte[] signed = sign(data);
            return Base64Utils.encodeBase64URL(signed).equals(expected);
        } catch (JWTSignException e) {
            throw new JWTValidationException(e.getMessage());
        }
    }


}
