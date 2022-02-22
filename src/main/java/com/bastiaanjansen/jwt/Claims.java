package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class Claims {
    protected final Map<String, Object> claims;

    protected Claims() {
        claims = new HashMap<>();
    }

    public boolean containsClaim(String name) {
        return claims.containsKey(name);
    }

    public Map<String, Object> getAsMap() {
        return new HashMap<>(claims);
    }

    public String base64Encoded() {
        String json = new JSONObject(claims).toString();
        return Base64Utils.encodeBase64URL(json);
    }

    public Object getClaim(String name) {
        return claims.get(name);
    }

    public <T> T getClaim(String name, Class<T> type) {
        Object value = claims.get(name);
        return type.cast(value);
    }

    public <T> T getClaim(String name, ClaimConverter<T> converter) {
        Object value = claims.get(name);
        return converter.convert(value);
    }

    public void addClaim(String name, Object value) {
        if (name == null) throw new IllegalArgumentException("name cannot be null");
        if (value == null) throw new IllegalArgumentException("value cannot be null");
        claims.put(name, value);
    }
}
