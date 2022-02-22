package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTException;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

public class App {
    public static void main(String[] args) throws JWTCreationException {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        JWT.Builder builder = new JWT.Builder(algorithm);

        JWT jwt = builder.build();

        System.out.println(jwt.sign());
    }
}

