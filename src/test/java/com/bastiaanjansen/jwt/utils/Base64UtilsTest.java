package com.bastiaanjansen.jwt.utils;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class Base64UtilsTest {

    @Test
    void encodeBase64URLWithString() {
        String data = "data";
        String expected = "ZGF0YQ";

        assertThat(Base64Utils.encodeBase64URL(data), is(expected));
    }

    @Test
    void encodeBase64URLWithBytes() {
        byte[] data = "data".getBytes();
        String expected = "ZGF0YQ";

        assertThat(Base64Utils.encodeBase64URL(data), is(expected));
    }

    @Test
    void decodeBase64URL() {
        String encoded = "ZGF0YQ";
        String expected = "data";

        assertThat(Base64Utils.decodeBase64URL(encoded), is(expected));
    }

}