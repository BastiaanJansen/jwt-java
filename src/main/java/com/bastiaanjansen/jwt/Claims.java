package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.utils.Base64Utils;
import org.json.JSONObject;

import java.util.*;
import java.util.stream.Collectors;

public class Claims {
    private final Registered[] registeredDateClaims = { Registered.EXPIRATION_TIME, Registered.ISSUED_AT, Registered.NOT_BEFORE };
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
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String name, Class<T> type) {
        Object value = claims.get(name);

        boolean isDateClaim = Arrays.stream(registeredDateClaims)
                .map(Claims.Registered::getValue)
                .collect(Collectors.toList())
                .contains(name);

        if (isDateClaim) {
            long millisSinceEpoch = Long.parseLong(String.valueOf(value));
            return (T) new Date(millisSinceEpoch);
        }

        return type.cast(value);
    }

    public <T> T getClaim(String name, ClaimParser<T> parser) {
        Object value = claims.get(name);
        return parser.parse(value);
    }

    public void addClaim(String name, Object value) {
        if (name == null) throw new IllegalArgumentException("name cannot be null");
        if (value == null) throw new IllegalArgumentException("value cannot be null");
        claims.put(name, value);
    }

    public enum Registered {
        ISSUER("iss"),
        SUBJECT("sub"),
        AUDIENCE("aud"),
        EXPIRATION_TIME("exp"),
        NOT_BEFORE("nbf"),
        ISSUED_AT("iat"),
        JWT_ID("jti"),
        TYPE("typ"),
        CONTENT_TYPE("cty"),
        ALGORITHM("alg");

        private final String value;

        Registered(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
}
