package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

import java.util.Date;
import java.util.Map;

public class DefaultJWTVerifier implements JWTVerifier {

    private final JWT jwt;
    private final Header headerConditions;
    private final Payload payloadConditions;

    public DefaultJWTVerifier(JWT jwt) {
        this(new Builder(jwt).withType("JWT"));
    }

    public DefaultJWTVerifier(Builder builder) {
        this.jwt = builder.jwt;
        this.headerConditions = builder.header;
        this.payloadConditions = builder.payload;

    }

    @Override
    public void verify() throws JWTValidationException {
        verifyHeader();
        verifyPayload();
//        if (payload.getExpirationTime() != null) {
//            Object payloadExpirationDate = payload.getExpirationTime();
//            if (LocalDate.now().compareTo(LocalDate.parse(payloadExpirationDate.toString())) < 0)
//                return false;
//        }

        if (!jwt.getAlgorithm().verify(jwt))
            throw new JWTValidationException("Signature is not valid");
    }

    private void verifyHeader() throws JWTValidationException {
        Header header = jwt.getHeader();
        for (Map.Entry<String, Object> condition: headerConditions.entrySet()) {
            if (!header.containsKey(condition.getKey()))
                throw new JWTValidationException(condition.getKey() + " is not present in header");

            if (!header.get(condition.getKey()).equals(condition.getValue()))
                throw new JWTValidationException(condition.getKey() + " is not " + condition.getValue());
        }
    }

    private void verifyPayload() throws JWTValidationException {
        Payload payload = jwt.getPayload();
    }

    public static class Builder {
        private final Header header;
        private final Payload payload;
        private final JWT jwt;

        public Builder(JWT jwt) {
            this.header = new Header();
            this.payload = new Payload();
            this.jwt = jwt;
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

        public DefaultJWTVerifier build() {
            return new DefaultJWTVerifier(this);
        }
    }
}
