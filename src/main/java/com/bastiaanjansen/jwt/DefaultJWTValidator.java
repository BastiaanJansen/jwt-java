package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTExpiredException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;
import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

/**
 * Default implementation of a JWT verifier.
 *
 * @author Bastiaan Jansen
 * @see JWTValidator
 */
public class DefaultJWTValidator implements JWTValidator {

    private final Header headerConditions;
    private final Payload payloadConditions;

    public DefaultJWTValidator() {
        this(new Builder().withType("JWT"));
    }

    public DefaultJWTValidator(Builder builder) {
        this.headerConditions = builder.header;
        this.payloadConditions = builder.payload;
    }

    @Override
    public void validate(JWT jwt) throws JWTValidationException {
        verifyHeader(jwt.getHeader());
        verifyPayload(jwt.getPayload());

        String encodedHeaders = Base64Utils.encodeBase64URL(new JSONObject(jwt.getHeader()).toString());
        String encodedPayload = Base64Utils.encodeBase64URL(new JSONObject(jwt.getPayload()).toString());

        String concatinated = encodedHeaders + "." + encodedPayload;
        if (!jwt.getAlgorithm().verify(concatinated.getBytes(StandardCharsets.UTF_8), jwt.getSignature()))
            throw new JWTValidationException("Signature is not valid");
    }

    private void verifyHeader(Header header) throws JWTValidationException {
        for (Map.Entry<String, Object> condition: headerConditions.entrySet()) {
            if (!header.containsKey(condition.getKey()))
                throw new JWTValidationException(condition.getKey() + " is not present in header");

            if (!header.get(condition.getKey()).equals(condition.getValue()))
                throw new JWTValidationException(condition.getKey() + " is not " + condition.getValue());
        }
    }

    private void verifyPayload(Payload payload) throws JWTValidationException {
        Date currentDate = new Date();

        if (payload.containsKey(Payload.Registered.EXPIRATION_TIME)) {
            Date expirationTime = payload.getExpirationTime();
            if (currentDate.getTime() > expirationTime.getTime())
                throw new JWTExpiredException("JWT expired on " + expirationTime);
        }

        // Checks that if the not-before (nbf) claim is set, the current date is after or equal to the not-before date.
        if (payload.containsKey(Payload.Registered.NOT_BEFORE)) {
            Date notBefore = payload.getNotBefore();
            if (currentDate.getTime() <= notBefore.getTime())
                throw new JWTValidationException("JWT is only valid after " + notBefore);
        }

        for (Map.Entry<String, Object> condition: payloadConditions.entrySet()) {
            if (!payload.containsKey(condition.getKey()))
                throw new JWTValidationException(condition.getKey() + " is not present in payload");

            if (!payload.get(condition.getKey()).equals(condition.getValue()))
                throw new JWTValidationException(condition.getKey() + " is not " + condition.getValue());
        }
    }

    public static class Builder {
        private final Header header;
        private final Payload payload;

        public Builder() {
            this.header = new Header();
            this.payload = new Payload();
        }

        public Builder withType(String type) {
            header.setType(type);
            return this;
        }

        public Builder withContentType(String type) {
            header.setContentType(type);
            return this;
        }

        public Builder withAlgorithm(String algorithm) {
            header.setAlgorithm(algorithm);
            return this;
        }

        public Builder withIssuer(String issuer) {
            payload.setIssuer(issuer);
            return this;
        }

        public Builder withSubject(String subject) {
            payload.setSubject(subject);
            return this;
        }

        public Builder withAudience(String audience) {
            payload.setAudience(audience);
            return this;
        }

        public Builder withExpirationTime(Date expirationTime) {
            payload.setExpirationTime(expirationTime.getTime());
            return this;
        }

        public Builder withNotBefore(Date notBefore) {
            payload.setNotBefore(notBefore.getTime());
            return this;
        }

        public Builder withIssuedAt(Date issuedAt) {
            payload.setIssuedAt(issuedAt.getTime());
            return this;
        }

        public Builder withID(String id) {
            payload.setID(id);
            return this;
        }

        public Builder withClaim(String name, Object value) {
            payload.put(name, value);
            return this;
        }

        public DefaultJWTValidator build() {
            return new DefaultJWTValidator(this);
        }
    }

    public Header getHeaderConditions() {
        return headerConditions;
    }

    public Payload getPayloadConditions() {
        return payloadConditions;
    }
}
