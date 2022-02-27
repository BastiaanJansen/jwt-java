package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.algorithms.Algorithm;
import com.bastiaanjansen.jwt.exceptions.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class DefaultJWTValidatorTest {

    private Algorithm algorithm;

    @BeforeEach
    void setUp() {
        this.algorithm = Algorithm.HMAC384("secret".getBytes());
    }

    @AfterEach
    void tearDown() {
        this.algorithm = null;
    }

    @Test
    void validate_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).build();
        JWTValidator validator = new DefaultJWTValidator();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidSignature_throwsJWTValidationException() throws JWTCreationException, JWTDecodeException {
        String jwtString = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR";
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        JWTValidator validator = new DefaultJWTValidator();

        assertThrows(JWTValidationException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithExpirationTimeInPast_throwsJWTExpiredException() throws JWTCreationException {
        Date past = new Date(100);
        JWT jwt = new JWT.Builder(algorithm).withExpirationTime(past).build();
        JWTValidator validator = new DefaultJWTValidator();

        assertThrows(JWTExpiredException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithExpirationTimeInFuture_doesNotThrow() throws JWTCreationException {
        Date future = Date.from(Instant.now().plusSeconds(1000));
        JWT jwt = new JWT.Builder(algorithm).withExpirationTime(future).build();
        JWTValidator validator = new DefaultJWTValidator();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithValidType_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withType("JWT").build();
        JWTValidator validator = new DefaultJWTValidator();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidType_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withType("type").build();
        JWTValidator validator = new DefaultJWTValidator();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidContentType_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withContentType("invalid").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withContentType("content-type").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidContentType_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withContentType("content-type").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withContentType("content-type").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidAlgorithm_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withAlgorithm("invalid").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidAlgorithm_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withAlgorithm("HS384").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidIssuer_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withIssuer("issuer").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withIssuer("invalid").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidIssuer_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withIssuer("issuer").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withIssuer("issuer").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidSubject_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withSubject("subject").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withSubject("invalid").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidSubject_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withSubject("issuer").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withSubject("issuer").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidAudience_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withAudience("aud1", "aud2").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withOneOfAudience("invalid").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidAudience_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withAudience("aud1", "aud2").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withOneOfAudience("aud1").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithValidAllAudience_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withAudience("aud1", "aud2", "aud3").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withAllOfAudience("aud1", "aud2").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithValidAllAudience_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withAudience("aud1", "aud3").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withAllOfAudience("aud1", "aud2").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidExpirationDate_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withExpirationTime(100).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withExpirationTime(200).build();

        assertThrows(JWTExpiredException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidExpirationDate_doesNotThrow() throws JWTCreationException {
        Date date = Date.from(Instant.now().plusSeconds(100));
        JWT jwt = new JWT.Builder(algorithm).withExpirationTime(date).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withExpirationTime(date).build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidNotBefore_throwsJWTValidationException() throws JWTCreationException {
        Date date = Date.from(Instant.now().plusSeconds(100));
        JWT jwt = new JWT.Builder(algorithm).withNotBefore(date).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withNotBefore(100).build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidNotBefore_doesNotThrow() throws JWTCreationException {
        Date date = Date.from(Instant.now().minusSeconds(100));
        JWT jwt = new JWT.Builder(algorithm).withNotBefore(date).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withNotBefore(date).build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidIssuedAt_throwsJWTValidationException() throws JWTCreationException {
        Date date = new Date(100);
        JWT jwt = new JWT.Builder(algorithm).withIssuedAt(date).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withIssuedAt(200).build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidIssuedAt_doesNotThrow() throws JWTCreationException {
        Date date = new Date(100);
        JWT jwt = new JWT.Builder(algorithm).withNotBefore(date).build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withNotBefore(date).build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithInvalidID_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withID("id").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withID("invalid").build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithValidID_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withID("id").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withID("id").build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithHeader_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withHeader("test", "value").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withHeader("test", "value"::equals).build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithHeader_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withHeader("test", "value").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withHeader("test", "invalid"::equals).build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithClaim_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withClaim("test", "value").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withClaim("test", "value"::equals).build();

        assertDoesNotThrow(() -> validator.validate(jwt));
    }

    @Test
    void validateWithClaim_throwsJWTValidationException() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withClaim("test", "value").build();
        JWTValidator validator = new DefaultJWTValidator.Builder().withClaim("test", "invalid"::equals).build();

        assertThrows(InvalidClaimException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateWithHeaderNameIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withHeader(null, "value"));
    }

    @Test
    void validateWithHeaderValueIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withHeader("name", null));
    }

    @Test
    void validateWithCustomHeaderNameIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withHeader(null, value -> false));
    }

    @Test
    void validateWithCustomHeaderValidatorIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withHeader("name", null));
    }

    @Test
    void validateWithClaimNameIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withClaim(null, "value"));
    }

    @Test
    void validateWithClaimValueIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withClaim("name", null));
    }

    @Test
    void validateWithCustomClaimNameIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withClaim(null, value -> false));
    }

    @Test
    void validateWithCustomClaimValidatorIsNull_throwsIllegalArgumentException() {
        DefaultJWTValidator.Builder builder = new DefaultJWTValidator.Builder();

        assertThrows(IllegalArgumentException.class, () -> builder.withClaim("name", null));
    }
}