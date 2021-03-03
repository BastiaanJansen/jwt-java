package com.bastiaanjansen.jwt.Algorithms;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class HMACAlgorithmTest {

    private HMACAlgorithm algorithm;

    @BeforeEach
    void setUp() {
        this.algorithm = new HMACAlgorithm("HS512", "HmacSHA256", "KKSDSDBSJDBAPKSDHYUSD".getBytes(StandardCharsets.UTF_8));
    }

    @AfterEach
    void tearDown() {
        this.algorithm = null;
    }

    @Test
    void sign() {
        assertDoesNotThrow(() -> {
            byte[] signed = algorithm.sign("data".getBytes(StandardCharsets.UTF_8));
            String signedBase64URLEncoded = Base64.getUrlEncoder().encodeToString(signed);
            assertEquals(signedBase64URLEncoded, "zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8=");
        });
    }

    @Test
    void signWithString() {
        assertDoesNotThrow(() -> {
            byte[] signed = algorithm.sign("data");
            String signedBase64URLEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signed);
            assertEquals(signedBase64URLEncoded, "zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8");
        });
    }

    @Test
    void verify() {
//        assertDoesNotThrow(() -> {
//            boolean isValid = algorithm.verify("data".getBytes(StandardCharsets.UTF_8), "zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8");
//            assertTrue(isValid);
//        });
    }
}