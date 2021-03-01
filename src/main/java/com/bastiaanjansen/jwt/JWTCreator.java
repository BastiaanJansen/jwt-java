package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.SignException;
import org.json.JSONObject;

public class JWTCreator {

    private final Algorithm algorithm;
    private final JSONObject claims;
    private final JSONObject header;

    JWTCreator(Builder builder) {
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

        Builder(Algorithm algorithm) {
            if (algorithm == null)
                throw new IllegalArgumentException("Algorithm must not be null");

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.header = new HashMap<>();

            withHeader(Header.Registered.ALGORITHM, algorithm.getName());
        }

        public Builder withTypeHeader(String type) {
            withHeader(Header.Registered.TYPE, type);
            return this;
        }

        public Builder withContentTypeHeader(String contentType) {
            withHeader(Header.Registered.CONTENT_TYPE, contentType);
            return this;
        }

        public Builder withIssuer(String issuer) {
            withClaim(Claim.Registered.ISSUER, issuer);
            return this;
        }

        public Builder withSubject(String subject) {
            withClaim(Claim.Registered.SUBJECT, subject);
            return this;
        }

        public Builder withAudience(String audience) {
            withClaim(Claim.Registered.AUDIENCE, audience);
            return this;
        }

        public Builder withExpirationTime(Date expirationTime) {
            withClaim(Claim.Registered.EXPIRATION_TIME, expirationTime);
            return this;
        }

        public Builder withNotBefore(Date notBefore) {
            withClaim(Claim.Registered.NOT_BEFORE, notBefore);
            return this;
        }

        public Builder withIssuedAt(Date issuedAt) {
            withClaim(Claim.Registered.ISSUED_AT, issuedAt);
            return this;
        }

        public Builder withID(String id) {
            withClaim(Claim.Registered.JWT_ID, id);
            return this;
        }

        public void withHeader(String name, String value) {
            if (value == null) throw new IllegalArgumentException("Header value cannot be null");
            header.put(name, value);
        }

        public void withClaim(String name, Object value) {
            if (value == null) throw new IllegalArgumentException("Claim value cannot be null");
            claims.put(name, value);
        }

        public String sign() throws JWTCreationException {
            if (!header.containsKey(Header.Registered.TYPE))
                withTypeHeader("JWT");
            return new JWTCreator(this).sign();
        }

    }
}
