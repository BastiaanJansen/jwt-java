package com.bastiaanjansen.jwt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

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
    void typeIsByDefaultJWT() {
        assertTrue(header.containsKey(Header.Registered.TYPE));
        assertEquals(header.getType(), "JWT");
    }

    @Test
    void createHeaderWithMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(Header.Registered.TYPE, "type");
        map.put(Header.Registered.ALGORITHM, "HS512");
        header = new Header(map);
        assertTrue(header.containsKey(Header.Registered.TYPE));
        assertTrue(header.containsKey(Header.Registered.ALGORITHM));
        assertEquals(header.getType(), "type");
        assertEquals(header.getAlgorithm(), "HS512");
    }

    @Test
    void setType() {
        header.setType("type");
        assertTrue(header.containsKey(Header.Registered.TYPE));
    }

    @Test
    void getType() {
        header.setType("type");
        assertEquals(header.getType(), "type");
    }

    @Test
    void setContentType() {
        header.setContentType("contentType");
        assertTrue(header.containsKey(Header.Registered.CONTENT_TYPE));
    }

    @Test
    void getContentType() {
        header.setContentType("contentType");
        assertEquals(header.getContentType(), "contentType");
    }

    @Test
    void setAlgorithm() {
        header.setAlgorithm("algorithm");
        assertTrue(header.containsKey(Header.Registered.ALGORITHM));
    }

    @Test
    void getAlgorithm() {
        header.setAlgorithm("algorithm");
        assertEquals(header.getAlgorithm(), "algorithm");
    }
}