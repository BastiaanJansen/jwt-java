package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;

import java.nio.charset.StandardCharsets;
import java.util.*;

import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;
import com.bastiaanjansen.jwt.Exceptions.SignException;
import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * @author Bastiaan Jansen
 */
public class JWT {

    private final Algorithm algorithm;
    private final Header header;
    private final Payload payload;
    private final String signature;

    public JWT(Algorithm algorithm, Header header, Payload payload) throws JWTCreationException {
        this.algorithm = algorithm;
        this.header = header;
        this.payload = payload;
        this.signature = createSignature();
    }

    private JWT(Algorithm algorithm, Header header, Payload payload, String signature) {
        this.algorithm = algorithm;
        this.header = header;
        this.payload = payload;
        this.signature = signature;
    }

    private JWT(Builder builder) throws JWTCreationException {
        algorithm = builder.algorithm;
        payload = builder.payload;
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

            return new JWT(algorithm, new Header(header.toMap()), new Payload(payload.toMap()), signature);
        } catch (JSONException e) {
            throw new JWTCreationException("JSON is not valid");
        }
    }

    /**
     * Checks whether the JWT is valid
     *
     */
    public void verify(JWTVerifier verifier) throws JWTValidationException {
        verifier.verify();
    }

    public void verify() throws JWTValidationException {
        verify(new DefaultJWTVerifier(this));
    }

    public static class Builder implements JWTBuilder {

        private final Algorithm algorithm;
        private final Header header;
        private final Payload payload;

        /**
         * Creates a new JWT Builder instance
         *
         * @param algorithm algorithm to use when signing JWT
         */
        public Builder(Algorithm algorithm) {
            if (algorithm == null)
                throw new IllegalArgumentException("Algorithm must not be null");

            this.algorithm = algorithm;
            this.header = new Header();
            this.payload = new Payload();

            header.setAlgorithm(algorithm.getName());
        }

        /**
         * Add type (typ) claim to header
         *
         * @param type type header
         * @return the same builder instance
         */
        public Builder withType(String type) {
            header.setType(type);
            return this;
        }

        /**
         * Add a content type (cty) claim to header
         *
         * @param contentType content type value
         * @return the same builder instance
         */
        public Builder withContentType(String contentType) {
            header.setContentType(contentType);
            return this;
        }

        /**
         * Add an issuer (iss) claim to payload
         *
         * @param issuer issuer value
         * @return the same builder instance
         */
        public Builder withIssuer(String issuer) {
            payload.setIssuer(issuer);
            return this;
        }

        /**
         * Add a subject (sub) claim to payload
         *
         * @param subject subject value
         * @return the same builder instance
         */
        public Builder withSubject(String subject) {
            payload.setSubject(subject);
            return this;
        }

        /**
         * Add an audience (aud) claim to payload
         *
         * @param audience audience value
         * @return the same builder instance
         */
        public Builder withAudience(String audience) {
            payload.setAudience(audience);
            return this;
        }

        /**
         * Add a expiration time (exp) to payload
         *
         * @param expirationTime expiration time as date
         * @return the same builder instance
         */
        public Builder withExpirationTime(Date expirationTime) {
            payload.setExpirationTime(expirationTime.getTime());
            return this;
        }

        /**
         * Add a not before (nbf) claim to payload
         *
         * @param notBefore not before date
         * @return the same builder instance
         */
        public Builder withNotBefore(Date notBefore) {
            payload.setNotBefore(notBefore.getTime());
            return this;
        }

        /**
         * Add a issued at (iat) claim to payload
         *
         * @param issuedAt issued at date
         * @return the same builder instance
         */
        public Builder withIssuedAt(Date issuedAt) {
            payload.setIssuedAt(issuedAt.getTime());
            return this;
        }

        /**
         * Add a key ID (kid) to the header claims
         *
         * @param id the key ID
         * @return the same builder instance
         */
        public Builder withID(String id) {
            payload.setID(id);
            return this;
        }

        /**
         * Add a header claim
         *
         * @param name name of header claim
         * @param value value of header claim
         */
        public Builder withHeader(String name, String value) {
            if (value == null) throw new IllegalArgumentException("Header value cannot be null");
            header.put(name, value);
            return this;
        }

        /**
         * Add a claim to the payload
         *
         * @param name name of payload claim
         * @param value value of payload claim
         */
        public Builder withClaim(String name, Object value) {
            if (value == null) throw new IllegalArgumentException("Claim value cannot be null");
            payload.put(name, value);
            return this;
        }

        /**
         * Add multiple claims to payload
         *
         * @param claims the values used in the payload
         */
        public Builder withClaim(Map<String, ?> claims) {
            for (Map.Entry<String, ?> claim: claims.entrySet())
                withClaim(claim.getKey(), claim.getValue());
            return this;
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

    public Payload getPayload() {
        return payload;
    }

    public Header getHeader() {
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
        String encodedHeaders = Base64Utils.encodeBase64URL(new JSONObject(header).toString());
        String encodedPayload = Base64Utils.encodeBase64URL(new JSONObject(payload).toString());

        String signature = createSignature(encodedHeaders, encodedPayload);

        return String.format("%s.%s.%s", encodedHeaders, encodedPayload, signature);
    }

    /**
     * Create signature based on algorithm, header and payload
     *
     * @return Created signature
     * @throws JWTCreationException when Sign exception occurs
     */
    private String createSignature(String encodedHeaders, String encodedPayload) throws JWTCreationException {
        try {
            byte[] signed = algorithm.sign((encodedHeaders + "." + encodedPayload).getBytes(StandardCharsets.UTF_8));
            return Base64Utils.encodeBase64URL(signed);
        } catch (SignException e) {
            throw new JWTCreationException("Something went wrong creating JWT");
        }
    }

    private String createSignature() throws JWTCreationException {
        String encodedHeaders = Base64Utils.encodeBase64URL(new JSONObject(header).toString());
        String encodedPayload = Base64Utils.encodeBase64URL(new JSONObject(payload).toString());
        return createSignature(encodedHeaders, encodedPayload);
    }
}
