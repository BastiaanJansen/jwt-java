package com.bastiaanjansen.jwt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PayloadTest {

    private Payload payload;

    @BeforeEach
    void setUp() {
        this.payload = new Payload();
    }

    @AfterEach
    void tearDown() {
        this.payload = null;
    }

    @Test
    void createHeaderWithMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(Payload.Registered.ISSUER, "issuer");
        map.put(Payload.Registered.JWT_ID, "id");
        payload = new Payload(map);
        assertTrue(payload.containsKey(Payload.Registered.ISSUER));
        assertTrue(payload.containsKey(Payload.Registered.JWT_ID));
        assertEquals(payload.getIssuer(), "issuer");
        assertEquals(payload.getID(), "id");
    }

    @Test
    void setIssuer() {
        payload.setIssuer("issuer");
        assertTrue(payload.containsKey(Payload.Registered.ISSUER));
    }

    @Test
    void getIssuer() {
        payload.setIssuer("issuer");
        assertEquals(payload.getIssuer(), "issuer");
    }

    @Test
    void setSubject() {
        payload.setSubject("subject");
        assertTrue(payload.containsKey(Payload.Registered.SUBJECT));
    }

    @Test
    void getSubject() {
        payload.setSubject("subject");
        assertEquals(payload.getSubject(), "subject");
    }

    @Test
    void setAudience() {
        payload.setAudience("audience");
        assertTrue(payload.containsKey(Payload.Registered.AUDIENCE));
    }

    @Test
    void getAudience() {
        payload.setAudience("audience");
        assertArrayEquals(payload.getAudience(), new String[]{ "audience" });
    }

    @Test
    void setExpirationTime() {
        payload.setExpirationTime(new Date());
        assertTrue(payload.containsKey(Payload.Registered.EXPIRATION_TIME));
    }

    @Test
    void testSetExpirationTime() {
        payload.setExpirationTime(239872398);
        assertTrue(payload.containsKey(Payload.Registered.EXPIRATION_TIME));
    }

    @Test
    void getExpirationTime() {
        Date currentDate = new Date();
        payload.setExpirationTime(currentDate);
        assertEquals(payload.getExpirationTime(), currentDate);
    }

    @Test
    void setNotBefore() {
        payload.setNotBefore(new Date());
        assertTrue(payload.containsKey(Payload.Registered.NOT_BEFORE));
    }

    @Test
    void testSetNotBefore() {
        payload.setNotBefore(239872398);
        assertTrue(payload.containsKey(Payload.Registered.NOT_BEFORE));
    }

    @Test
    void getNotBefore() {
        Date currentDate = new Date();
        payload.setNotBefore(currentDate);
        assertEquals(payload.getNotBefore(), currentDate);
    }

    @Test
    void setIssuedAt() {
        payload.setIssuedAt(new Date());
        assertTrue(payload.containsKey(Payload.Registered.ISSUED_AT));
    }

    @Test
    void testSetIssuedAt() {
        payload.setIssuedAt(239872398);
        assertTrue(payload.containsKey(Payload.Registered.ISSUED_AT));
    }

    @Test
    void getIssuedAt() {
        Date currentDate = new Date();
        payload.setIssuedAt(currentDate);
        assertEquals(payload.getIssuedAt(), currentDate);
    }

    @Test
    void setID() {
        payload.setID("id");
        assertTrue(payload.containsKey(Payload.Registered.JWT_ID));
    }

    @Test
    void getID() {
        payload.setID("id");
        assertEquals(payload.getID(), "id");
    }
}