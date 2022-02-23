package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.utils.Base64Utils;
import org.json.JSONObject;

import java.util.Map;

public class Header extends Claims {
    public static class Registered {
        static String TYPE = "typ";
        static String CONTENT_TYPE = "cty";
        static String ALGORITHM = "alg";
    }

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
        addClaim(Registered.TYPE, type);
    }

    public String getType() {
        return getClaim(Registered.TYPE, String.class);
    }

    public void setContentType(String value) {
        addClaim(Registered.CONTENT_TYPE, value);
    }

    public String getContentType() {
        return getClaim(Registered.CONTENT_TYPE, String.class);
    }

    public void setAlgorithm(String algorithm) {
        addClaim(Registered.ALGORITHM, algorithm);
    }

    public String getAlgorithm() {
        return getClaim(Registered.ALGORITHM, String.class);
    }
}
