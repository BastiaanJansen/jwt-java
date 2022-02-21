package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class Header {
    public static class Registered {
        static String TYPE = "typ";
        static String CONTENT_TYPE = "cty";
        static String ALGORITHM = "alg";
    }

    private final Map<String, Object> claims;

    public Header() {
        claims = new HashMap<>();
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
        Object type = claims.get(Registered.TYPE);
        return getString(type);
    }

    public void setContentType(String value) {
        addClaim(Registered.CONTENT_TYPE, value);
    }

    public String getContentType() {
        Object contentType = claims.get(Registered.CONTENT_TYPE);
        return getString(contentType);
    }

    public void setAlgorithm(String algorithm) {
        addClaim(Registered.ALGORITHM, algorithm);
    }

    public String getAlgorithm() {
        Object algorithm = claims.get(Registered.ALGORITHM);
        return getString(algorithm);
    }

    public boolean containsClaim(String name) {
        return claims.containsKey(name);
    }

    public Map<String, Object> getAsMap() {
        return new HashMap<>(claims);
    }

    public String base64Encoded() {
        return Base64Utils.encodeBase64URL(new JSONObject(claims).toString());
    }

    public Object getClaim(String name) {
        return claims.get(name);
    }

    public void addClaim(String name, Object value) {
        if (name == null) throw new IllegalArgumentException("name cannot be null");
        if (value == null) throw new IllegalArgumentException("value cannot be null");

        claims.put(name, value);
    }

    private String getString(Object object) {
        return object != null ? String.valueOf(object) : null;
    }
}
