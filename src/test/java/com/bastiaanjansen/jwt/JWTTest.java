package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    void fromRawJWT() {
        assertDoesNotThrow(() -> {
            JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");
        });
    }

    @Test
    void fromRawMalformedJWT() {
        assertThrows(JWTException.class, () -> {
            JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIssdsdjkhInR5cCI6IkpXVCJ9shdkshdsdssdljs.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");
        });
    }

    @Test
    void verify() {
        assertDoesNotThrow(() -> {
            JWT jwt = JWT.fromRawJWT(algorithm, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1");
            jwt.verify();
        });
    }

    @Test
    void testVerify() {
    }

    @Test
    void sign() {
    }
}