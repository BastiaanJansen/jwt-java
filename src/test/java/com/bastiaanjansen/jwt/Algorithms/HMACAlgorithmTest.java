package com.bastiaanjansen.jwt.Algorithms;

import com.bastiaanjansen.jwt.Exceptions.JWTSignException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class HMACAlgorithmTest {

    private HMACAlgorithm algorithm;

    @BeforeEach
    void setUp() {
        this.algorithm = new HMACAlgorithm("HS512", "HmacSHA256", "KKSDSDBSJDBAPKSDHYUSD".getBytes());
    }

    @AfterEach
    void tearDown() {
        this.algorithm = null;
    }

    @Test
    void sign_doesNotThrow() {
        assertDoesNotThrow(() -> algorithm.sign("data".getBytes()));
    }

    @Test
    void sign() throws JWTSignException {
        byte[] signed = algorithm.sign("data".getBytes());
        String signedBase64URLEncoded = Base64.getUrlEncoder().encodeToString(signed);
        String expected = "zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8=";

        assertThat(signedBase64URLEncoded, is(expected));
    }

    @Test
    void signWithString_doesNotThrow() {
        assertDoesNotThrow(() -> algorithm.sign("data"));
    }

    @Test
    void signWithString() throws JWTSignException {
        byte[] signed = algorithm.sign("data");
        String signedBase64URLEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signed);
        String expected = "zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8";

        assertThat(signedBase64URLEncoded, is(expected));
    }

    @Test
    void verify_doesNotThrow() {
        assertDoesNotThrow(() -> {
            algorithm.verify("data".getBytes(), Base64.getUrlDecoder().decode("zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8"));
        });
    }

    @Test
    void verifyExpectedIsCorrect() throws JWTValidationException {
        boolean isValid = algorithm.verify("data".getBytes(), Base64.getUrlDecoder().decode("zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U8"));

        assertThat(isValid, is(true));
    }

    @Test
    void verifyExpectedIsIncorrect() throws JWTValidationException {
        boolean isValid = algorithm.verify("data".getBytes(), Base64.getUrlDecoder().decode("zbOa_v86tCj1m7nx3ZGDEq6urhQ4ROmcKbXcbQjK-U"));

        assertThat(isValid, is(false));
    }
}