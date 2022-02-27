package com.bastiaanjansen.jwt.algorithms;

import com.bastiaanjansen.jwt.exceptions.JWTSignException;
import com.bastiaanjansen.jwt.exceptions.JWTValidationException;

import java.security.*;

public class RSAAlgorithm extends Algorithm {

    private final KeyPair keyPair;

    protected RSAAlgorithm(String name, String jcaName, KeyPair keyPair, int minKeyLength) {
        super(name, jcaName, keyPair.getPrivate(), minKeyLength);
        this.keyPair = keyPair;
    }

    @Override
    public byte[] sign(byte[] data) throws JWTSignException {
        try {
            final Signature signature = Signature.getInstance(jcaName);
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
            final Signature signature = Signature.getInstance(jcaName);
            signature.initVerify(keyPair.getPublic());
            signature.update(data);

            return signature.verify(expected);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new JWTValidationException(e.getMessage());
        }
    }
}
