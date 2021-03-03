package com.bastiaanjansen.jwt;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Payload extends HashMap<String, Object> {
    public static class Registered {
        static String ISSUER = "iss";
        static String SUBJECT = "sub";
        static String AUDIENCE = "aud";
        static String EXPIRATION_TIME = "exp";
        static String NOT_BEFORE = "nbf";
        static String ISSUED_AT = "iat";
        static String JWT_ID = "jti";
    }

    public Payload() {}

    public Payload(Map<String, Object> map) {
        putAll(map);
    }

    public void setIssuer(String issuer) {
        set(Registered.ISSUER, issuer);
    }

    public String getIssuer() {
        Object issuer = get(Registered.ISSUER);
        return getString(issuer);
    }

    public void setSubject(String subject) {
        set(Registered.SUBJECT, subject);
    }

    public String getSubject() {
        Object subject = get(Registered.SUBJECT);
        return getString(subject);
    }

    public void setAudience(String... audience) {
        set(Registered.AUDIENCE, audience);
    }

    public String[] getAudience() {
        Object[] audience = (Object[]) get(Registered.AUDIENCE);
        return (String[]) audience;
    }

    public void setExpirationTime(long timeSinceEpoch) {
        set(Registered.EXPIRATION_TIME, timeSinceEpoch);
    }

    public void setExpirationTime(Date expirationTime) {
        setExpirationTime(expirationTime.getTime());
    }

    public Date getExpirationTime() {
        Object expirationDate = get(Registered.EXPIRATION_TIME);
        return getDate(expirationDate);
    }

    public void setNotBefore(long timeSinceEpoch) {
        set(Registered.NOT_BEFORE, timeSinceEpoch);
    }

    public void setNotBefore(Date notBefore) {
        setNotBefore(notBefore.getTime());
    }

    public Date getNotBefore() {
        Object notBefore = get(Registered.NOT_BEFORE);
        return getDate(notBefore);
    }

    public void setIssuedAt(long timeSinceEpoch) {
        set(Registered.ISSUED_AT, timeSinceEpoch);
    }

    public void setIssuedAt(Date issuedAt) {
        setIssuedAt(issuedAt.getTime());
    }

    public Date getIssuedAt() {
        Object issuedAt = get(Registered.ISSUED_AT);
        return getDate(issuedAt);
    }

    public void setID(String id) {
        set(Registered.JWT_ID, id);
    }

    public String getID() {
        Object id = get(Registered.JWT_ID);
        return getString(id);
    }

    private void set(String name, Object value) {
        if (name == null) throw new IllegalArgumentException("name cannot be null");
        if (value == null) throw new IllegalArgumentException("value cannot be null");
        put(name, value);
    }

    private String getString(Object object) {
        return object != null ? String.valueOf(object) : null;
    }

    private Date getDate(Object object) {
        if (object == null)
            return null;

        if (object instanceof Number) {
            long millis = ((Number) object).longValue();
            return new Date(millis);
        }

        throw new IllegalStateException("Cannot create date from " + object);
    }
}
