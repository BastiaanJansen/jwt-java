package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;

import java.nio.charset.StandardCharsets;
import java.util.*;

import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;
import com.bastiaanjansen.jwt.Exceptions.SignException;
import org.json.JSONObject;

/**
 * @author Bastiaan Jansen
 */
public class JWT {

    private final Algorithm algorithm;
    private final JSONObject header;
    private final JSONObject claims;

    public JWT(Algorithm algorithm, JSONObject header, JSONObject claims) {
        this.algorithm = algorithm;
        this.header = header;
        this.claims = claims;
    }

    public JWT(Algorithm algorithm, String jwt) throws JWTDecodeException {

        String[] segments = jwt.split("\\.");

        if (segments.length != 3)
            throw new JWTDecodeException("The number of segments is not 3");

        this.algorithm = algorithm;
        this.header = new JSONObject(decodeBase64URL(segments[0]));
        this.claims = new JSONObject(decodeBase64URL(segments[1]));
    }

    private JWT(Builder builder) {
        algorithm = builder.algorithm;
        claims = mapToJSON(builder.claims);
        header = mapToJSON(builder.header);
    }

    public String sign() throws JWTCreationException {
        String headerBase64URLEncoded = encodeBase64URL(header.toString());
        String claimsBase64URLEncoded = encodeBase64URL(claims.toString());
        return String.format("%s.%s.%s", headerBase64URLEncoded, claimsBase64URLEncoded, createSignature());
    }

    private JSONObject mapToJSON(Map<String, ?> json) {
        return new JSONObject(json);
    }

    private String encodeBase64URL(String data) {
        return encodeBase64URL(data.getBytes(StandardCharsets.UTF_8));
    }

    private String encodeBase64URL(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private String decodeBase64URL(String encoded) {
        byte[] decoded = Base64.getUrlDecoder().decode(encoded);
        return new String(decoded);
    }

    private String createSignature() throws JWTCreationException {
        String headerBase64URLEncoded = encodeBase64URL(header.toString());
        String claimsBase64URLEncoded = encodeBase64URL(claims.toString());

        try {
            byte[] signed = algorithm.sign((headerBase64URLEncoded + "." + claimsBase64URLEncoded).getBytes(StandardCharsets.UTF_8));
            return encodeBase64URL(signed);
        } catch (SignException e) {
            throw new JWTCreationException("Something went wrong creating JWT");
        }
    }

    public static class Builder {

        private final Algorithm algorithm;
        private final Map<String, Object> claims;
        private final Map<String, Object> header;

        /**
         * Creates a new JWT Builder instance
         *
         * @param algorithm algorithm to use when signing JWT
         */
        public Builder(Algorithm algorithm) {
            if (algorithm == null)
                throw new IllegalArgumentException("Algorithm must not be null");

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.header = new HashMap<>();

            withHeader(Header.Registered.ALGORITHM, algorithm.getName());
        }

        /**
         * Add type (typ) claim to header
         *
         * @param type type header
         * @return the same builder instance
         */
        public Builder withType(String type) {
            withHeader(Header.Registered.TYPE, type);
            return this;
        }

        /**
         * Add a content type (cty) claim to header
         *
         * @param contentType content type value
         * @return the same builder instance
         */
        public Builder withContentType(String contentType) {
            withHeader(Header.Registered.CONTENT_TYPE, contentType);
            return this;
        }

        /**
         * Add an issuer (iss) claim to payload
         *
         * @param issuer issuer value
         * @return the same builder instance
         */
        public Builder withIssuer(String issuer) {
            withClaim(Claim.Registered.ISSUER, issuer);
            return this;
        }

        /**
         * Add a subject (sub) claim to payload
         *
         * @param subject subject value
         * @return the same builder instance
         */
        public Builder withSubject(String subject) {
            withClaim(Claim.Registered.SUBJECT, subject);
            return this;
        }

        /**
         * Add an audience (aud) claim to payload
         *
         * @param audience audience value
         * @return the same builder instance
         */
        public Builder withAudience(String audience) {
            withClaim(Claim.Registered.AUDIENCE, audience);
            return this;
        }

        /**
         * Add a expiration time (exp) to payload
         *
         * @param expirationTime expiration time as date
         * @return the same builder instance
         */
        public Builder withExpirationTime(Date expirationTime) {
            withClaim(Claim.Registered.EXPIRATION_TIME, expirationTime);
            return this;
        }

        /**
         * Add a not before (nbf) claim to payload
         *
         * @param notBefore not before date
         * @return the same builder instance
         */
        public Builder withNotBefore(Date notBefore) {
            withClaim(Claim.Registered.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Add a issued at (iat) claim to payload
         *
         * @param issuedAt issued at date
         * @return the same builder instance
         */
        public Builder withIssuedAt(Date issuedAt) {
            withClaim(Claim.Registered.ISSUED_AT, issuedAt);
            return this;
        }

        /**
         * Add a key ID (kid) to the header claims
         *
         * @param id the key ID
         * @return the same builder instance
         */
        public Builder withID(String id) {
            withHeader(Claim.Registered.JWT_ID, id);
            return this;
        }

        /**
         * Add a header claim
         *
         * @param name name of header claim
         * @param value value of header claim
         */
        public void withHeader(String name, String value) {
            if (value == null) throw new IllegalArgumentException("Header value cannot be null");
            header.put(name, value);
        }

        /**
         * Add a claim to the payload
         *
         * @param name name of payload claim
         * @param value value of payload claim
         */
        public void withClaim(String name, Object value) {
            if (value == null) throw new IllegalArgumentException("Claim value cannot be null");
            claims.put(name, value);
        }

        /**
         * Add multiple claims to payload
         *
         * @param claims the values used in the payload
         */
        public void withClaim(Map<String, ?> claims) {
            for (Map.Entry<String, ?> claim: claims.entrySet())
                withClaim(claim.getKey(), claim.getValue());
        }

        /**
         * Creates a new JWT
         *
         * @return a new JWT
         * @throws JWTCreationException when the JWT could not be created
         */
        public String sign() throws JWTCreationException {
            if (!header.containsKey(Header.Registered.TYPE))
                withTypeHeader("JWT");
            return new JWT(this).sign();
        }

        /**
         * Creates a new JWT with additional payload
         *
         * @param payload map of additional payload
         * @return A new JWT
         * @throws JWTCreationException when the JWT could not be created
         */
        public String sign(Map<String, ?> payload) throws JWTCreationException {
            withClaim(payload);
            return sign();
        }

        /**
         * Create a new JWT instance
         *
         * @return New JWT instance
         */
        public JWT build() {
            return new JWT(this);
        }
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public JSONObject getClaims() {
        return claims;
    }

    public JSONObject getHeader() {
        return header;
    }
}
