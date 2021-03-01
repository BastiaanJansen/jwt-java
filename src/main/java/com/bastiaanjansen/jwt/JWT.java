package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;

import java.nio.charset.StandardCharsets;
import java.util.*;

import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;
import com.bastiaanjansen.jwt.Exceptions.SignException;
import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * @author Bastiaan Jansen
 */
public class JWT {

    private final Algorithm algorithm;
    private final Map<String, ?> header;
    private final Map<String, ?> payload;
    private final String signature;

    public JWT(Algorithm algorithm, Map<String, ?> header, Map<String, ?> payload) throws JWTCreationException {
        this.algorithm = algorithm;
        this.header = header;
        this.payload = payload;
        this.signature = createSignature();
    }

    private JWT(Algorithm algorithm,  Map<String, ?> header,  Map<String, ?> payload, String signature) {
        this.algorithm = algorithm;
        this.header = header;
        this.payload = payload;
        this.signature = signature;
    }

    private JWT(Builder builder) throws JWTCreationException {
        algorithm = builder.algorithm;
        payload = builder.claims;
        header = builder.header;
        signature = createSignature();
    }

    /**
     * Create a new JWT instance based on a raw JWT
     *
     * @param algorithm algorithm to use when signing JWT
     * @param jwt Raw JWT
     * @return Newly created JWT instance
     * @throws JWTDecodeException When the raw JWT could not be decoded
     */
    public static JWT fromRawJWT(Algorithm algorithm, String jwt) throws JWTDecodeException, JWTCreationException {
        String[] segments = jwt.split("\\.");

        if (segments.length != 3)
            throw new JWTDecodeException("The number of segments is not 3");

        try {
            JSONObject header = new JSONObject(Base64Utils.decodeBase64URL(segments[0]));
            JSONObject payload = new JSONObject(Base64Utils.decodeBase64URL(segments[1]));
            String signature = segments[2];

            return new JWT(algorithm, header.toMap(), payload.toMap(), signature);
        } catch (JSONException e) {
            throw new JWTCreationException("JSON is not valid");
        }
    }

    /**
     * Checks whether the JWT is valid
     *
     * @return True when JWT is valid, false otherwise
     */
    public boolean verify(JWTVerifier verifier) {
        return verifier.verify();
    }

    public boolean verify() {
        return verify(new DefaultJWTVerifier(this));
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
                withType("JWT");
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
        public JWT build() throws JWTCreationException {
            return new JWT(this);
        }
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public  Map<String, ?> getPayload() {
        return payload;
    }

    public  Map<String, ?> getHeader() {
        return header;
    }

    public String getSignature() {
        return signature;
    }

    /**
     * Create a new JWT
     *
     * @return A new JWT
     * @throws JWTCreationException when JWT could not be created
     */
    public String sign() throws JWTCreationException {
        String headerBase64URLEncoded = Base64Utils.encodeBase64URL(new JSONObject(header).toString());
        String payloadBase64URLEncoded = Base64Utils.encodeBase64URL(new JSONObject(payload).toString());

        return String.format("%s.%s.%s", headerBase64URLEncoded, payloadBase64URLEncoded, createSignature());
    }

    /**
     * Create signature based on algorithm, header and payload
     *
     * @return Created signature
     * @throws JWTCreationException when Sign exception occurs
     */
    private String createSignature() throws JWTCreationException {
        String headerBase64URLEncoded = Base64Utils.encodeBase64URL(new JSONObject(header).toString());
        String payloadBase64URLEncoded = Base64Utils.encodeBase64URL(new JSONObject(payload).toString());

        try {
            byte[] signed = algorithm.sign((headerBase64URLEncoded + "." + payloadBase64URLEncoded).getBytes(StandardCharsets.UTF_8));
            return Base64Utils.encodeBase64URL(signed);
        } catch (SignException e) {
            throw new JWTCreationException("Something went wrong creating JWT");
        }
    }
}
