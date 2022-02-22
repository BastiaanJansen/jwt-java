package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONObject;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Payload extends Claims {
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
        claims.putAll(map);
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
        return getClaim(Registered.ISSUER, String.class);
    }

    public void setSubject(String subject) {
        addClaim(Registered.SUBJECT, subject);
    }

    public String getSubject() {
        return getClaim(Registered.SUBJECT, String.class);
    }

    public void setAudience(String... audience) {
        addClaim(Registered.AUDIENCE, audience);
    }

    public String[] getAudience() {
        Object audience = getClaim(Registered.AUDIENCE, Object.class);

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
        return getClaim(Registered.EXPIRATION_TIME, Date.class);
    }

    public void setNotBefore(long timeSinceEpoch) {
        addClaim(Registered.NOT_BEFORE, timeSinceEpoch);
    }

    public void setNotBefore(Date notBefore) {
        setNotBefore(notBefore.getTime());
    }

    public Date getNotBefore() {
        return getClaim(Registered.NOT_BEFORE, Date.class);
    }

    public void setIssuedAt(long timeSinceEpoch) {
        addClaim(Registered.ISSUED_AT, timeSinceEpoch);
    }

    public void setIssuedAt(Date issuedAt) {
        setIssuedAt(issuedAt.getTime());
    }

    public Date getIssuedAt() {
        return getClaim(Registered.ISSUED_AT, Date.class);
    }

    public void setID(String id) {
        addClaim(Registered.JWT_ID, id);
    }

    public String getID() {
        return getClaim(Registered.JWT_ID, String.class);
    }
}
