package com.bastiaanjansen.jwt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
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
    void constructorWithMap_getID() {
        Map<String, Object> map = new HashMap<>();
        map.put(Payload.Registered.ISSUER, "issuer");
        map.put(Payload.Registered.JWT_ID, "id");
        String expected = "id";

        payload = new Payload(map);

        assertThat(payload.getID(), is(expected));
    }

    @Test
    void constructorWithMap_getIssuer() {
        Map<String, Object> map = new HashMap<>();
        map.put(Payload.Registered.ISSUER, "issuer");
        map.put(Payload.Registered.JWT_ID, "id");
        String expected = "issuer";

        payload = new Payload(map);

        assertThat(payload.getIssuer(), is(expected));
    }

    @Test
    void setIssuer() {
        payload.setIssuer("issuer");
        String expected = "issuer";

        assertThat(payload.getIssuer(), is(expected));
    }

    @Test
    void setSubject() {
        payload.setSubject("subject");
        String expected = "subject";

        assertThat(payload.getSubject(), is(expected));
    }

    @Test
    void setAudience() {
        payload.setAudience("audience");
        String[] expected = { "audience" };

        assertThat(payload.getAudience(), is(expected));
    }

    @Test
    void setExpirationTime() {
        Date date = new Date(100);
        payload.setExpirationTime(date);

        assertThat(payload.getExpirationTime(), is(date));
    }

    @Test
    void testSetExpirationTime() {
        payload.setExpirationTime(239872398);
        Date expected = new Date(239872398L);

        assertThat(payload.getExpirationTime(), is(expected));
    }

    @Test
    void setNotBefore() {
        Date date = new Date(100);
        payload.setNotBefore(date);

        assertThat(payload.getNotBefore(), is(date));
    }

    @Test
    void setIssuedAt() {
        Date date = new Date(100);
        payload.setIssuedAt(date);

        assertThat(payload.getIssuedAt(), is(date));
    }

    @Test
    void setID() {
        payload.setID("id");
        String expected = "id";

        assertThat(payload.getID(), is(expected));
    }

    @Test
    void base64EncodedWithEmptyPayload() {
        String expected = "e30";

        assertThat(payload.base64Encoded(), is(expected));
    }

    @Test
    void base64EncodedWithIssuer() {
        payload.setIssuer("issuer");
        String expected = "eyJpc3MiOiJpc3N1ZXIifQ";

        assertThat(payload.base64Encoded(), is(expected));
    }

    @Test
    void getClaimAsString() {
        payload.addClaim("key", "value");
        String expected = "value";

        assertThat(payload.getClaim("key", String.class), is(expected));
    }

    @Test
    void getClaimAsInteger() {
        payload.addClaim("key", 100);
        int expected = 100;

        assertThat(payload.getClaim("key", Integer.class), is(expected));
    }

    @Test
    void getClaimAsLong() {
        payload.addClaim("key", 100L);
        long expected = 100;

        assertThat(payload.getClaim("key", Long.class), is(expected));
    }

    @Test
    void getClaimConverted() {
        payload.addClaim("key", "value");
        String expected = "VALUE";

        assertThat(payload.getClaim("key", value -> String.valueOf(value).toUpperCase()), is(expected));
    }
}