package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;

public class App {
    public static void main(String[] args) {
//        Algorithm algorithm = Algorithm.HMAC256("secret");
        Algorithm algorithm = Algorithm.HMAC384("secret");
        JWT.Builder builder = new JWT.Builder(algorithm);

        builder.withIssuer("issuer");

        try {
            String jwt = builder.sign();
            System.out.println(jwt);

            JWT newJWT = JWT.fromRawJWT(algorithm, jwt);
            System.out.println(newJWT.getPayload());
        } catch (JWTCreationException | JWTDecodeException e) {
            e.printStackTrace();
        }
    }
}

