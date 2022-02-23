package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.utils.Base64Utils;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Claims {
    private final String[] registeredDateClaims = { Payload.Registered.EXPIRATION_TIME, Payload.Registered.ISSUED_AT, Payload.Registered.NOT_BEFORE };
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

    /**
     * Get a claim by name and cast it to a specific type
     *
     * @param name of the claim
     * @param type of the claim
     * @param <T> type of the claim
     * @return claim value cast to specified type
     */
    public <T> T getClaim(String name, Class<T> type) {
        Object value = claims.get(name);

        boolean isDateClaim = Arrays.asList(registeredDateClaims).contains(name);

        if (isDateClaim) {
            long millisSinceEpoch = Long.parseLong(String.valueOf(value));
            value = new Date(millisSinceEpoch);
        }

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
