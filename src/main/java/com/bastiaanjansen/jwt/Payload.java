package com.bastiaanjansen.jwt;

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

    public void setIssuer(Object issuer) {
        put(Registered.ISSUER, issuer);
    }

    public Object getIssuer() {
        return get(Registered.ISSUER);
    }

    public void setSubject(Object subject) {
        put(Registered.SUBJECT, subject);
    }

    public Object getSubject() {
        return get(Registered.SUBJECT);
    }

    public void setAudience(Object audience) {
        put(Registered.AUDIENCE, audience);
    }

    public Object getAudience() {
        return get(Registered.AUDIENCE);
    }

    public void setExpirationTime(long timeSinceEpoch) {
        put(Registered.EXPIRATION_TIME, timeSinceEpoch);
    }

    public Object getExpirationTime() {
        return get(Registered.EXPIRATION_TIME);
    }

    public void setNotBefore(long timeSinceEpoch) {
        put(Registered.NOT_BEFORE, timeSinceEpoch);
    }

    public Object getNotBefore() {
        return get(Registered.NOT_BEFORE);
    }

    public void setIssuedAt(long timeSinceEpoch) {
        put(Registered.ISSUED_AT, timeSinceEpoch);
    }

    public Object getIssuedAt() {
        return get(Registered.ISSUED_AT);
    }

    public void setID(String id) {
        put(Registered.JWT_ID, id);
    }

    public Object getID() {
        return get(Registered.JWT_ID);
    }
}
