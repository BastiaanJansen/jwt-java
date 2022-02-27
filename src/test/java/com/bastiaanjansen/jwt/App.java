package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.algorithms.Algorithm;
import com.bastiaanjansen.jwt.exceptions.JWTCreationException;

public class App {
    public static void main(String[] args) throws JWTCreationException {
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        JWT.Builder builder = new JWT.Builder(algorithm);

        JWT jwt = builder.build();

        System.out.println(jwt.sign());
    }
}

