package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JWTTest {

    private Algorithm algorithm;

    @BeforeEach
    void setUp() {
        this.algorithm = Algorithm.HMAC384("secret");
    }

    @AfterEach
    void tearDown() {
        this.algorithm = null;
    }

    @Test
    void createFromBuilder() {
        Date now = new Date();

        JWT.Builder builder = new JWT.Builder(algorithm);

        assertDoesNotThrow(() -> {
            JWT jwt = builder
                    .withContentType("contentType")
                    .withID("id")
                    .withIssuer("issuer")
                    .withAudience("aud1", "aud2")
                    .withSubject("subject")
                    .withIssuedAt(now)
                    .withNotBefore(now)
                    .withExpirationTime(now)
                    .withClaim("customClaim", "customClaimValue")
                    .withHeader("customHeaderClaim", "customHeaderClaimValue")
                    .build();

            Header header = jwt.getHeader();
            Payload payload = jwt.getPayload();

            assertEquals(header.getContentType(), "contentType");
            assertEquals(header.getType(), "JWT");
            assertEquals(header.getAlgorithm(), "HS384");
            assertEquals(payload.getID(), "id");
            assertEquals(payload.getIssuer(), "issuer");
            assertArrayEquals(payload.getAudience(), new String[]{ "aud1", "aud2" });
            assertEquals(payload.getSubject(), "subject");
            assertEquals(payload.getIssuedAt(), now);
            assertEquals(payload.getNotBefore(), now);
            assertEquals(payload.getExpirationTime(), now);
            assertEquals(payload.get("customClaim"), "customClaimValue");
            assertEquals(header.get("customHeaderClaim"), "customHeaderClaimValue");
        });
    }

    @Test
    void fromRawJWT() {
        assertDoesNotThrow(() -> {
            JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");
        });
    }

    @Test
    void fromRawMalformedJWT() {
        assertThrows(JWTCreationException.class, () -> {
            JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIssdsdjkhInR5cCI6IkpXVCJ9shdkshdsdssdljs.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");
        });
    }

    @Test
    void validate() {
        assertDoesNotThrow(() -> {
            JWT jwt = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");
            jwt.validate();
        });
    }

    @Test
    void sign() {
        assertDoesNotThrow(() -> {
            String jwt = new JWT.Builder(algorithm)
                    .sign();
            assertEquals(jwt, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.nx2GHSOLOGjofcETRXDMFQfkhN3YB-B5WMieLPkIM0MazzxtHN0YpuV5OMyQvx3r");
        });
    }
}