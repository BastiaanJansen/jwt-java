package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.utils.Base64Utils;
import org.json.JSONObject;

import java.util.Map;

public final class Header extends Claims {

    public Header() {
        setType("JWT");
    }

    public Header(Map<String, Object> map) {
        this();
        claims.putAll(map);
    }

    public static Header fromBase64EncodedJSON(String encodedJSON) {
        String decodedJSON = Base64Utils.decodeBase64URL(encodedJSON);
        Map<String, Object> map = new JSONObject(decodedJSON).toMap();
        return new Header(map);
    }

    public void setType(String type) {
        addClaim(Registered.TYPE.getValue(), type);
    }

    public String getType() {
        return getClaim(Registered.TYPE.getValue(), String.class);
    }

    public void setContentType(String value) {
        addClaim(Registered.CONTENT_TYPE.getValue(), value);
    }

    public String getContentType() {
        return getClaim(Registered.CONTENT_TYPE.getValue(), String.class);
    }

    public void setAlgorithm(String algorithm) {
        addClaim(Registered.ALGORITHM.getValue(), algorithm);
    }

    public String getAlgorithm() {
        return getClaim(Registered.ALGORITHM.getValue(), String.class);
    }
}
