package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONObject;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Payload {
    public static class Registered {
        static String ISSUER = "iss";
        static String SUBJECT = "sub";
        static String AUDIENCE = "aud";
        static String EXPIRATION_TIME = "exp";
        static String NOT_BEFORE = "nbf";
        static String ISSUED_AT = "iat";
        static String JWT_ID = "jti";
    }

    private final Map<String, Object> claims;

    public Payload() {
        claims = new HashMap<>();
    }

    public Payload(Map<String, Object> map) {
        claims = new HashMap<>(map);
    }

    public static Payload fromBase64EncodedJSON(String encodedJSON) {
        String decodedJSON = Base64Utils.decodeBase64URL(encodedJSON);
        Map<String, Object> map = new JSONObject(decodedJSON).toMap();
        return new Payload(map);
    }

    public void setIssuer(String issuer) {
        addClaim(Registered.ISSUER, issuer);
    }

    public String getIssuer() {
        Object issuer = claims.get(Registered.ISSUER);
        return getString(issuer);
    }

    public void setSubject(String subject) {
        addClaim(Registered.SUBJECT, subject);
    }

    public String getSubject() {
        Object subject = claims.get(Registered.SUBJECT);
        return getString(subject);
    }

    public void setAudience(String... audience) {
        addClaim(Registered.AUDIENCE, audience);
    }

    public String[] getAudience() {
        Object audience = claims.get(Registered.AUDIENCE);

        if (!(audience instanceof Object[]))
            return new String[] {(String) audience};

        return (String[]) audience;
    }

    public void setExpirationTime(long timeSinceEpoch) {
        addClaim(Registered.EXPIRATION_TIME, timeSinceEpoch);
    }

    public void setExpirationTime(Date expirationTime) {
        setExpirationTime(expirationTime.getTime());
    }

    public Date getExpirationTime() {
        Object expirationDate = claims.get(Registered.EXPIRATION_TIME);
        return getDate(expirationDate);
    }

    public void setNotBefore(long timeSinceEpoch) {
        addClaim(Registered.NOT_BEFORE, timeSinceEpoch);
    }

    public void setNotBefore(Date notBefore) {
        setNotBefore(notBefore.getTime());
    }

    public Date getNotBefore() {
        Object notBefore = claims.get(Registered.NOT_BEFORE);
        return getDate(notBefore);
    }

    public void setIssuedAt(long timeSinceEpoch) {
        addClaim(Registered.ISSUED_AT, timeSinceEpoch);
    }

    public void setIssuedAt(Date issuedAt) {
        setIssuedAt(issuedAt.getTime());
    }

    public Date getIssuedAt() {
        Object issuedAt = claims.get(Registered.ISSUED_AT);
        return getDate(issuedAt);
    }

    public void setID(String id) {
        addClaim(Registered.JWT_ID, id);
    }

    public String getID() {
        Object id = claims.get(Registered.JWT_ID);
        return getString(id);
    }

    public boolean containsClaim(String name) {
        return claims.containsKey(name);
    }

    public void addClaim(String name, Object value) {
        if (name == null) throw new IllegalArgumentException("name cannot be null");
        if (value == null) throw new IllegalArgumentException("value cannot be null");
        claims.put(name, value);
    }

    public Object get(String name) {
        return claims.get(name);
    }

    public Map<String, Object> getAsMap() {
        return new HashMap<>(claims);
    }

    public String base64Encoded() {
        return Base64Utils.encodeBase64URL(new JSONObject(claims).toString());
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
