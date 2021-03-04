package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
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
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {

//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048, new SecureRandom());
//        KeyPair pair = keyPairGenerator.generateKeyPair();

//        System.out.println("Public: " + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
//        System.out.println("Private: " + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));

        String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm5PpsWJJvL3W+N0wiLniRbbrKx5qhxob/1hEfEzCOQLwl8pbO5UiuTE7nhdvHyCmQhAexpKIL0PRpKwHEWNN/KOxAZ5xdSIZU6W44Inq/hkK5ugbCViV4ONnpz+I1XoDNAi4ITJVpIPyqu2r4C4BTAZnozca8fe7p6VYzECnP3OZT+ELota4TRy3G5W6WIFayftGuvx0dncJOgy6SUaNuUBs2t9KXFHmxfYCz78WLq3QWDz21f1siqib+qHAdH5aNlPAkpqyP2hPLoc8VHKKs+Eb0QlkpW9ZABoybrHCWnPI1C4mdLMQ4MWqEgKKWvqrjDZDBfRfk6U/VUDuneQ9ZwIDAQAB";
        String privateKeyContent = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbk+mxYkm8vdb43TCIueJFtusrHmqHGhv/WER8TMI5AvCXyls7lSK5MTueF28fIKZCEB7GkogvQ9GkrAcRY038o7EBnnF1IhlTpbjgier+GQrm6BsJWJXg42enP4jVegM0CLghMlWkg/Kq7avgLgFMBmejNxrx97unpVjMQKc/c5lP4Qui1rhNHLcblbpYgVrJ+0a6/HR2dwk6DLpJRo25QGza30pcUebF9gLPvxYurdBYPPbV/WyKqJv6ocB0flo2U8CSmrI/aE8uhzxUcoqz4RvRCWSlb1kAGjJuscJac8jULiZ0sxDgxaoSAopa+quMNkMF9F+TpT9VQO6d5D1nAgMBAAECggEATT58SiktyTtMb9WKkmgQc2KlkowQgjGxcu9FWZ3W1O2jvQmokIW0btSF8DFcZ80THzvXu+nnGeiHP0Z2X+i5QNWZPd+IH4slngVrLHjtpumSIyFcwyArkjP2M/D0pGFnE7+8hCb0pLEqnDlTHARben63mC70/uxsTIlo9EipgXPCOBDAd/QsE3dhlO4SbEmCJMQR6eV1B8an+40ZbhQCG8IO832jDiDYabS5tyOPgU2ahG5UhzqsfPFQBlgJ2ePPyXXYaQlS1Gj8OD3ISJbCSxiitejbKjSaGsjoBv+81lkd3vqOYSZQDMf02rSRwp57mFfZ3G7Yk9lS+Q8abmUsyQKBgQDUtzLp3O+1363sT8lAjO9zWEXAqWT38mNaBqjR5c3Kv18xzm9LjTd9GfEgYgFmN6fkr1I85ZI35wR6pKjjJwUVci6615N2ghhTrcw9f8/zD/IejVPmYYIUdfRQ9FTlvM/RhDRCiyd1k7xQ/uGfy+Swu4bSzypzHUYeVQ6Xv5c/YwKBgQC7PEjjkzcLjn0EJcgnW11Md+Yrvg9NBKJO2JdMXfwRhN2NDAobbshJqaZeffgrTfU8KuGLmGNPE7UFnxOGnIVdDQwvjhde4LWuL/R6n10zu3tCmqvxBx7yzSO1+Ldi5bT9VI04x/gnGPQn489p0GBNWrN3AmC+RFXOridoVItTLQKBgBu3HvgfpFADK+sdXjB97HkP6E65A4HW4CELuxVWJuEi3ClmJ1QluzQenC9G9b22xLZkLYfntYx5GjlMmQC3xc7MiNApZHpNaxQEEhd1PsgBrN9UNLlQvR0jXUjq/ODOIBnBavm8ndCRBjlbbFRgwZRRariu624CQ2+ST4twGCnXAoGBAKvajGhdgiOYWEULTKhbIsqCLoCtxSuC+lr2UACnLysBUb0ZdNlzGGEMVwjaBIPy3QmprjVL3LMDOp77QJfIaFxdEnc/q1HJXNiRaYt3ZLuL9HnQr8reJ1jiU0m+DMy4XCQ9jBW27Z0tOUS3w3Oy8AFwI9MzGoro+/1lOgR3vR3NAoGAdmP0aPZfFHM6mdtkKVmNjPM8BTYhok+pEBzntNosUGqIT2u+TPFDV8aTYEti6mIrMVTO1mHRoqi9VL0WDHRT3IqTn3JE+KR2fUlMSE/PqW8MJ+70EhelgJj+bL6iyecnPqdquES57DYoFkdvqtz0qNL2gdzK5ay55YWgYbk0szw=";

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        Algorithm algorithm = Algorithm.RSA384(keyPair);
        JWT.Builder builder = new JWT.Builder(algorithm);

        Calendar now = Calendar.getInstance();
        now.add(Calendar.SECOND, -10);

//        builder
//                .withIssuer("issuer")
//                .withAudience("audience", "audience2")
//                .withID("id")
//                .withIssuedAt(new Date())
//                .withNotBefore(now.getTime())
//                .withClaim("username", "BastiaanJansen")
//                .withHeader("test", "test");

        builder.withClaim("sd", "sd");

        try {
            JWT jwt = builder.build();

//            JWT newJWT = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");

            jwt.validate();
//
            System.out.println("JWT: " + jwt.sign());
//
            jwt.validate();

//            JWTValidator verifier = new DefaultJWTValidator.Builder()
//                    .withType("JWT")
//                    .withNotBefore(now.getTime())
//                    .withOneOfAudience("audience")
//                    .withClaim("username", "BastiaanJansen"::equals)
//                    .withHeader("test", "test"::equals)
//                    .build();
//            verifier.validate(jwt);

            Payload payload = jwt.getPayload();

        } catch (JWTException e) {
            e.printStackTrace();
        }
    }
}

