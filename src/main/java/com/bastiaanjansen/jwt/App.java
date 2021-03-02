package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTException;

import java.util.Calendar;
import java.util.Date;

public class App {
    public static void main(String[] args) {
        Algorithm algorithm = Algorithm.HMAC384("secret");
        JWT.Builder builder = new JWT.Builder(algorithm);

        Calendar now = Calendar.getInstance();
        now.add(Calendar.SECOND, -10);

        builder
                .withIssuer("issuer")
                .withAudience("audience")
                .withID("id")
                .withIssuedAt(new Date())
                .withNotBefore(now.getTime());

        try {
            JWT jwt = builder.build();
//            System.out.println(jwt);

//            JWT newJWT = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9sds.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");

            JWTVerifier verifier = new DefaultJWTVerifier.Builder()
                    .withType("JWT")
                    .withIssuer("issuer")
                    .build();
            verifier.verify(jwt);

            Payload payload = jwt.getPayload();
//
            System.out.println(jwt.sign());
        } catch (JWTException e) {
            e.printStackTrace();
        }
    }
}

