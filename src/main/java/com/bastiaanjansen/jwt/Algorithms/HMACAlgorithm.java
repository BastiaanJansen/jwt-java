package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.SignException;
import com.bastiaanjansen.jwt.JWT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;

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

    @Override
    public boolean verify(JWT jwt) {
        try {
            String jwtString = jwt.sign();
            String[] segments = jwtString.split("\\.");
            String signature = segments[2];

            return signature.equals(jwt.getSignature());

        } catch (Exception e) {
            return false;
        }
    }


}
