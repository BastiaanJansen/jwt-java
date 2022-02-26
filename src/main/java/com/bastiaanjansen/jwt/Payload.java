package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.utils.Base64Utils;
import org.json.JSONObject;

import java.util.Date;
import java.util.Map;

public final class Payload extends Claims {

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
        addClaim(Registered.ISSUER.getValue(), issuer);
    }

    public String getIssuer() {
        return getClaim(Registered.ISSUER.getValue(), String.class);
    }

    public void setSubject(String subject) {
        addClaim(Registered.SUBJECT.getValue(), subject);
    }

    public String getSubject() {
        return getClaim(Claims.Registered.SUBJECT.getValue(), String.class);
    }

    public void setAudience(String... audience) {
        addClaim(Registered.AUDIENCE.getValue(), audience);
    }

    public String[] getAudience() {
        Object audience = getClaim(Registered.AUDIENCE.getValue(), Object.class);

        if (!(audience instanceof Object[]))
            return new String[] {(String) audience};

        return (String[]) audience;
    }

    public void setExpirationTime(long timeSinceEpoch) {
        addClaim(Registered.EXPIRATION_TIME.getValue(), timeSinceEpoch);
    }

    public void setExpirationTime(Date expirationTime) {
        setExpirationTime(expirationTime.getTime());
    }

    public Date getExpirationTime() {
        return getClaim(Registered.EXPIRATION_TIME.getValue(), Date.class);
    }

    public void setNotBefore(long timeSinceEpoch) {
        addClaim(Registered.NOT_BEFORE.getValue(), timeSinceEpoch);
    }

    public void setNotBefore(Date notBefore) {
        setNotBefore(notBefore.getTime());
    }

    public Date getNotBefore() {
        return getClaim(Registered.NOT_BEFORE.getValue(), Date.class);
    }

    public void setIssuedAt(long timeSinceEpoch) {
        addClaim(Registered.ISSUED_AT.getValue(), timeSinceEpoch);
    }

    public void setIssuedAt(Date issuedAt) {
        setIssuedAt(issuedAt.getTime());
    }

    public Date getIssuedAt() {
        return getClaim(Registered.ISSUED_AT.getValue(), Date.class);
    }

    public void setID(String id) {
        addClaim(Registered.JWT_ID.getValue(), id);
    }

    public String getID() {
        return getClaim(Registered.JWT_ID.getValue(), String.class);
    }
}
