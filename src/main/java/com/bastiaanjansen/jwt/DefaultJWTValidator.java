package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTExpiredException;
import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;
import com.bastiaanjansen.jwt.Utils.Base64Utils;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of a JWT verifier.
 *
 * @author Bastiaan Jansen
 * @see JWTValidator
 */
public class DefaultJWTValidator implements JWTValidator {

    private final Map<String, ClaimValidator> headerValidators;
    private final Map<String, ClaimValidator> payloadValidators;

    public DefaultJWTValidator() {
        this(new Builder().withType("JWT"));
    }

    public DefaultJWTValidator(Builder builder) {
        this.headerValidators = builder.headerValidators;
        this.payloadValidators = builder.payloadValidators;
    }

    @Override
    public void validate(JWT jwt) throws JWTValidationException {
        validateAlgorithm(jwt);
        verifyValidators(jwt.getHeader(), headerValidators);
        verifyPayload(jwt.getPayload());
    }

    private void validateAlgorithm(JWT jwt) throws JWTValidationException {
        String encodedHeaders = Base64Utils.encodeBase64URL(new JSONObject(jwt.getHeader()).toString());
        String encodedPayload = Base64Utils.encodeBase64URL(new JSONObject(jwt.getPayload()).toString());

        String concatenated = encodedHeaders + "." + encodedPayload;
        if (!jwt.getAlgorithm().verify(concatenated.getBytes(StandardCharsets.UTF_8), jwt.getSignature()))
            throw new JWTValidationException("Signature is not valid");
    }

    private void verifyValidators(Map<String, Object> map , Map<String, ClaimValidator> validators) throws JWTValidationException {
        for (Map.Entry<String, ClaimValidator> validatorEntry: validators.entrySet()) {
            String key = validatorEntry.getKey();
            ClaimValidator validator = validatorEntry.getValue();

            if (!map.containsKey(key))
                throw new JWTValidationException(key + " is not present in payload");

            if (map.get(key) == null)
                throw new JWTValidationException(key + " is null");

            if (!validator.validate(map.get(key)))
                throw new JWTValidationException(key + " does not conform to constraint");
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

        verifyValidators(payload, payloadValidators);
    }

    public static class Builder {
        private final Map<String, ClaimValidator> headerValidators;
        private final Map<String, ClaimValidator> payloadValidators;

        public Builder() {
            this.headerValidators = new HashMap<>();
            this.payloadValidators = new HashMap<>();
        }

        public Builder withType(String type) {
            withHeader(Header.Registered.TYPE, type::equals);
            return this;
        }

        public Builder withContentType(String type) {
            withHeader(Header.Registered.CONTENT_TYPE, type::equals);
            return this;
        }

        public Builder withAlgorithm(String algorithm) {
            withHeader(Header.Registered.ALGORITHM, algorithm::equals);
            return this;
        }

        public Builder withIssuer(String issuer) {
            withClaim(Payload.Registered.ISSUER, issuer::equals);
            return this;
        }

        public Builder withSubject(String subject) {
            withClaim(Payload.Registered.SUBJECT, subject::equals);
            return this;
        }

        public Builder withOneOfAudience(String... audience) {
            withClaim(Payload.Registered.AUDIENCE, value -> {
                for (String audienceItem: audience) {
                    if (Arrays.asList((Object[]) value).contains(audienceItem))
                        return true;
                }
                return false;
            });
            return this;
        }

        public Builder withExpirationTime(Date expirationTime) {
            withClaim(Payload.Registered.EXPIRATION_TIME, value -> value.equals(expirationTime.getTime()));
            return this;
        }

        public Builder withNotBefore(Date notBefore) {
            withClaim(Payload.Registered.NOT_BEFORE, value -> value.equals(notBefore.getTime()));
            return this;
        }

        public Builder withIssuedAt(Date issuedAt) {
            withClaim(Payload.Registered.ISSUED_AT, value -> value.equals(issuedAt.getTime()));
            return this;
        }

        public Builder withID(String id) {
            withClaim(Payload.Registered.JWT_ID, id::equals);
            return this;
        }

        public Builder withHeader(String name, Object value) {
            withHeader(name, value::equals);
            return this;
        }

        public Builder withHeader(String name, ClaimValidator validator) {
            if (name == null) throw new IllegalArgumentException("name cannot be null");
            if (validator == null) throw new IllegalArgumentException("validator cannot be null");

            headerValidators.put(name, validator);
            return this;
        }

        public Builder withClaim(String name, Object value) {
            withClaim(name, value::equals);
            return this;
        }

        public Builder withClaim(String name, ClaimValidator validator) {
            if (name == null) throw new IllegalArgumentException("name cannot be null");
            if (validator == null) throw new IllegalArgumentException("validator cannot be null");

            payloadValidators.put(name, validator);
            return this;
        }

        public DefaultJWTValidator build() {
            return new DefaultJWTValidator(this);
        }
    }

    public Map<String, ClaimValidator> getHeaderValidators() {
        return headerValidators;
    }

    public Map<String, ClaimValidator> getPayloadValidators() {
        return payloadValidators;
    }
}
