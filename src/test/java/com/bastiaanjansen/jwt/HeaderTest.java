package com.bastiaanjansen.jwt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class HeaderTest {

    private Header header;

    @BeforeEach
    void setUp() {
        this.header = new Header();
    }

    @AfterEach
    void tearDown() {
        this.header = null;
    }

    @Test
    void constructor_typeIsByDefaultJWT() {
        String expected = "JWT";

        assertThat(header.getType(), is(expected));
    }

    @Test
    void constructorWithMap_getType() {
        Map<String, Object> map = new HashMap<>();
        map.put(Header.Registered.TYPE, "type");
        map.put(Header.Registered.ALGORITHM, "HS512");
        String expected = "type";

        header = new Header(map);

        assertThat(header.getType(), is(expected));
    }

    @Test
    void constructorWithMap_getAlgorithm() {
        Map<String, Object> map = new HashMap<>();
        map.put(Header.Registered.TYPE, "type");
        map.put(Header.Registered.ALGORITHM, "HS512");
        String expected = "HS512";

        header = new Header(map);

        assertThat(header.getAlgorithm(), is(expected));
    }

    @Test
    void setType() {
        header.setType("type");
        String expected = "type";

        assertThat(header.getType(), is(expected));
    }

    @Test
    void setContentType() {
        header.setContentType("content-type");
        String expected = "content-type";

        assertThat(header.getContentType(), is(expected));
    }

    @Test
    void setAlgorithm() {
        header.setAlgorithm("algorithm");
        String expected = "algorithm";

        assertThat(header.getAlgorithm(), is(expected));
    }

    @Test
    void base64EncodedWithDefaultHeader() {
        String expected = "eyJ0eXAiOiJKV1QifQ";

        assertThat(header.base64Encoded(), is(expected));
    }

    @Test
    void base64EncodedWithType() {
        header.setType("type");
        String expected = "eyJ0eXAiOiJ0eXBlIn0";

        assertThat(header.base64Encoded(), is(expected));
    }
}