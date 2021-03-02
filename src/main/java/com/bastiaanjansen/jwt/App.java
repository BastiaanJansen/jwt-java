package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

public class App {
    public static void main(String[] args) {
        Algorithm algorithm = Algorithm.HMAC384("secret");
        JWT.Builder builder = new JWT.Builder(algorithm);

        builder
                .withIssuer("issuer")
                .withAudience("audience")
                .withID("id")
                .withIssuedAt(new Date());

        try {
            JWT jwt = builder.build();
//            System.out.println(jwt);

            JWT newJWT = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");

            JWTVerifier verifier = new DefaultJWTVerifier.Builder(newJWT)
                    .withType("JWT")
                    .build();
            verifier.verify();

            Payload payload = newJWT.getPayload();

            System.out.println(payload.getIssuedAt());

            System.out.println(jwt.sign());
        } catch (JWTCreationException | JWTDecodeException | JWTValidationException e) {
            e.printStackTrace();
        }
    }
}

