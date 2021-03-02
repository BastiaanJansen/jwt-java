package com.bastiaanjansen.jwt;

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
        put(Registered.ISSUER, issuer);
    }

    public String getIssuer() {
        Object issuer = get(Registered.ISSUER);
        return getString(issuer);
    }

    public void setSubject(String subject) {
        put(Registered.SUBJECT, subject);
    }

    public String getSubject() {
        Object subject = get(Registered.SUBJECT);
        return getString(subject);
    }

    public void setAudience(String audience) {
        put(Registered.AUDIENCE, audience);
    }

    public String getAudience() {
        Object audience = get(Registered.AUDIENCE);
        return getString(audience);
    }

    public void setExpirationTime(long timeSinceEpoch) {
        put(Registered.EXPIRATION_TIME, timeSinceEpoch);
    }

    public void setExpirationTime(Date expirationTime) {
        setExpirationTime(expirationTime.getTime());
    }

    public Date getExpirationTime() {
        Object expirationDate = get(Registered.EXPIRATION_TIME);
        return getDate(expirationDate);
    }

    public void setNotBefore(long timeSinceEpoch) {
        put(Registered.NOT_BEFORE, timeSinceEpoch);
    }

    public void setNotBefore(Date notBefore) {
        setNotBefore(notBefore.getTime());
    }

    public Date getNotBefore() {
        Object notBefore = get(Registered.NOT_BEFORE);
        return getDate(notBefore);
    }

    public void setIssuedAt(long timeSinceEpoch) {
        put(Registered.ISSUED_AT, timeSinceEpoch);
    }

    public void setIssuedAt(Date issuedAt) {
        setIssuedAt(issuedAt.getTime());
    }

    public Date getIssuedAt() {
        Object issuedAt = get(Registered.ISSUED_AT);
        return getDate(issuedAt);
    }

    public void setID(String id) {
        put(Registered.JWT_ID, id);
    }

    public String getID() {
        Object id = get(Registered.JWT_ID);
        return getString(id);
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
