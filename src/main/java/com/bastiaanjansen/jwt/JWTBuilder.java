package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;

import java.util.Date;
import java.util.Map;

public interface JWTBuilder {
    JWTBuilder withType(String type);
    JWTBuilder withContentType(String contentType);
    JWTBuilder withIssuer(String issuer);
    JWTBuilder withSubject(String subject);
    JWTBuilder withAudience(String audience);
    JWTBuilder withExpirationTime(Date expirationTime);
    JWTBuilder withNotBefore(Date notBefore);
    JWTBuilder withIssuedAt(Date issuedAt);
    JWTBuilder withID(String id);
    JWTBuilder withHeader(String name, String value);
    JWTBuilder withClaim(String name, Object value);
    JWTBuilder withClaim(Map<String, ?> claims);
    String sign() throws JWTCreationException;
    String sign(Map<String, ?> payload) throws JWTCreationException;
    JWT build() throws JWTCreationException;
}
