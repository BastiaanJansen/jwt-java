package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.JWTSignException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class RSAAlgorithm extends Algorithm {

    private final KeyPair keyPair;

    RSAAlgorithm(String name, String description, KeyPair keyPair) {
        super(name, description);
        this.keyPair = keyPair;
    }

    @Override
    public byte[] sign(String data) throws JWTSignException {
        return sign(data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] sign(byte[] data) throws JWTSignException {
        try {
            final Signature signature = Signature.getInstance(description);
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new JWTSignException(e.getMessage());
        }

    }

    @Override
    public boolean verify(byte[] data, byte[] expected) throws JWTValidationException {
        try {
            final Signature signature = Signature.getInstance(description);
            signature.initVerify(keyPair.getPublic());
            signature.update(data);

            return signature.verify(expected);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new JWTValidationException(e.getMessage());
        }
    }
}
