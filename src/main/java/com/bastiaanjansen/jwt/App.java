package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class App {
    public static void main(String[] args) {
        Algorithm algorithm = Algorithm.HMAC384("secret");
        JWT.Builder builder = new JWT.Builder(algorithm);

        builder
                .withIssuer("issuer")
                .withAudience("audience")
                .withID("id");

        try {
//            String jwt = builder.sign();
//            System.out.println(jwt);

            JWT newJWT = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIifQ.Aln1OLnguEiWmFJD1ZHflDV54JdeLLoWBFiBPwNh7g1GmQUVc3gMQ5q4zfdnPVdL");

            JWTVerifier verifier = new DefaultJWTVerifier.Builder(newJWT)
                    .withType("JWT")
                    .build();
            verifier.verify();

            System.out.println(newJWT.sign());
        } catch (JWTCreationException | JWTDecodeException | JWTValidationException e) {
            e.printStackTrace();
        }
    }
}

