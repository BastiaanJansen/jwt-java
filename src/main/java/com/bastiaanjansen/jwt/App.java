package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;

public class App {
    public static void main(String[] args) {
//        Algorithm algorithm = Algorithm.HMAC256("secret");
        Algorithm algorithm = Algorithm.HMAC384("secret");
        JWTCreator.Builder creator = new JWTCreator.Builder(algorithm);

        creator.withIssuer("issuer");

        try {
            String jwt = creator.sign();
            System.out.println(jwt);
        } catch (JWTCreationException e) {
            e.printStackTrace();
        }
    }
}

