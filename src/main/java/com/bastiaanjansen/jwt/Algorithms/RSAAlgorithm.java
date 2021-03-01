package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.SignException;
import com.bastiaanjansen.jwt.JWT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSAAlgorithm extends Algorithm {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    RSAAlgorithm(String name, String description, RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        super(name, description);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public byte[] sign(String data) throws SignException {
        return sign(data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] sign(byte[] data) throws SignException {
        try {
            final Signature signature = Signature.getInstance(name);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SignException(e.getMessage());
        }

    }

    @Override
    public boolean verify(JWT jwt) {
        return false;
    }
}
