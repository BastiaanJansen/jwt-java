package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Algorithms.Algorithm;
import com.bastiaanjansen.jwt.Exceptions.JWTCreationException;
import com.bastiaanjansen.jwt.Exceptions.JWTDecodeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class JWTTest {

    private Algorithm algorithm;
    private String jwtString;

    @BeforeEach
    void setUp() {
        this.algorithm = Algorithm.HMAC384("secret");
        this.jwtString = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1";
    }

    @AfterEach
    void tearDown() {
        this.algorithm = null;
        this.jwtString = null;
    }

    @Test
    void builder_doesNotThrow() {
       assertDoesNotThrow(() -> new JWT.Builder(algorithm).build());
    }

    @Test
    void builder_withType() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withType("type").build();
        String expected = "type";

        assertThat(jwt.getHeader().getType(), is(expected));
    }

    @Test
    void builder_withAlgorithm() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).build();

        assertThat(jwt.getAlgorithm(), is(algorithm));
    }

    @Test
    void builder_withContentType() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withContentType("content-type").build();
        String expected = "content-type";

        assertThat(jwt.getHeader().getContentType(), is(expected));
    }

    @Test
    void builder_withID() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withID("id").build();
        String expected = "id";

        assertThat(jwt.getPayload().getID(), is(expected));
    }

    @Test
    void builder_withIssuer() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withIssuer("issuer").build();
        String expected = "issuer";

        assertThat(jwt.getPayload().getIssuer(), is(expected));
    }

    @Test
    void builder_withEmptyAudience() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withAudience().build();
        String[] expected = {};

        assertThat(jwt.getPayload().getAudience(), is(expected));
    }

    @Test
    void builder_withAudience() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withAudience("aud1", "aud2").build();
        String[] expected = { "aud1", "aud2" };

        assertThat(jwt.getPayload().getAudience(), is(expected));
    }

    @Test
    void builder_withSubject() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withSubject("subject").build();
        String expected = "subject";

        assertThat(jwt.getPayload().getSubject(), is(expected));
    }

    @Test
    void builder_withIssuedAt() throws JWTCreationException {
        Date now = new Date();
        JWT jwt = new JWT.Builder(algorithm).withIssuedAt(now).build();

        assertThat(jwt.getPayload().getIssuedAt(), is(now));
    }

    @Test
    void builder_withNotBefore() throws JWTCreationException {
        Date now = new Date();
        JWT jwt = new JWT.Builder(algorithm).withNotBefore(now).build();

        assertThat(jwt.getPayload().getNotBefore(), is(now));
    }

    @Test
    void builder_withExpirationTime() throws JWTCreationException {
        Date now = new Date();
        JWT jwt = new JWT.Builder(algorithm).withExpirationTime(now).build();

        assertThat(jwt.getPayload().getExpirationTime(), is(now));
    }

    @Test
    void builder_withClaim() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withClaim("custom-claim", "custom-claim-value").build();
        String expected = "custom-claim-value";

        assertThat(jwt.getPayload().getClaim("custom-claim", String.class), is(expected));
    }

    @Test
    void builder_withHeader() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).withHeader("custom-header", "custom-header-value").build();
        String expected = "custom-header-value";

        assertThat(jwt.getHeader().getClaim("custom-header"), is(expected));
    }

    @Test
    void builder_withCustomHeader() throws JWTCreationException {
        Header header = new Header();
        JWT jwt = new JWT.Builder(algorithm).withHeader(header).build();

        assertThat(jwt.getHeader(), is(header));
    }

    @Test
    void builder_withCustomPayload() throws JWTCreationException {
        Payload payload = new Payload();
        JWT jwt = new JWT.Builder(algorithm).withPayload(payload).build();

        assertThat(jwt.getPayload(), is(payload));
    }

    @Test
    void builderWithHeaderIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(algorithm).withHeader(null).build());
    }

    @Test
    void builderWithHeaderNameIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(algorithm).withHeader(null, "value").build());
    }

    @Test
    void builderWithHeaderValueIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(algorithm).withHeader("name", null).build());
    }

    @Test
    void builderWithPayloadIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(algorithm).withPayload(null).build());
    }

    @Test
    void builderWithClaimNameIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(algorithm).withClaim(null, "value").build());
    }

    @Test
    void builderWithClaimValueIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(algorithm).withClaim("name", null).build());
    }

    @Test
    void builderAlgorithmIsNull_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new JWT.Builder(null).build());
    }

    @Test
    void fromRawJWT_doesNotThrow() {
        assertDoesNotThrow(() -> JWT.fromRawJWT(algorithm, jwtString));
    }

    @Test
    void fromRawJWT_typeIsJWT() throws JWTDecodeException, JWTCreationException {
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        String expected = "JWT";

        assertThat(jwt.getHeader().getType(), is(expected));
    }

    @Test
    void fromRawJWT_algorithmIsHS384() throws JWTDecodeException, JWTCreationException {
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        String expected = "HS384";

        assertThat(jwt.getHeader().getAlgorithm(), is(expected));
    }

    @Test
    void fromRawJWT_issuer() throws JWTDecodeException, JWTCreationException {
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        String expected = "issuer";

        assertThat(jwt.getPayload().getIssuer(), is(expected));
    }

    @Test
    void fromRawJWT_audience() throws JWTDecodeException, JWTCreationException {
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        String[] expected = { "audience" };

        assertThat(jwt.getPayload().getAudience(), is(expected));
    }

    @Test
    void fromRawJWT_id() throws JWTDecodeException, JWTCreationException {
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        String expected = "id";

        assertThat(jwt.getPayload().getID(), is(expected));
    }

    @Test
    void fromRawJWT_issuedAt() throws JWTDecodeException, JWTCreationException {
        JWT jwt = JWT.fromRawJWT(algorithm, jwtString);
        Date expected = new Date(1614676926172L);

        assertThat(jwt.getPayload().getIssuedAt(), is(expected));
    }

    @Test
    void fromRawMalformedJWT_throwsJWTCreationException() {
        String jwt = "eyJhbGciOiJIUzM4NCIssdsdjkhInR5cCI6IkpXVCJ9shdkshdsdssdljs.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImlhdCI6MTYxNDY3NjkyNjE3MiwianRpIjoiaWQifQ.ibsMduBXhE8Y1TkDAazH-J7BaAtcJTcwmHfzvQg9EWS6uKZFsA_7z4LYtSa-nnR1";

        assertThrows(JWTCreationException.class, () -> JWT.fromRawJWT(algorithm, jwt));
    }

    @Test
    void fromRawJWTWithTwoSegments_throwsJWTDecodeException() {
        String jwt = "segment1.segment2";

        assertThrows(JWTDecodeException.class, () -> JWT.fromRawJWT(algorithm, jwt));
    }

    @Test
    void fromRawJWTWithOneSegments_throwsJWTDecodeException() {
        String jwt = "segment1";

        assertThrows(JWTDecodeException.class, () -> JWT.fromRawJWT(algorithm, jwt));
    }

    @Test
    void fromRawJWTWithEmptyString_throwsJWTDecodeException() {
        String jwt = "";

        assertThrows(JWTDecodeException.class, () -> JWT.fromRawJWT(algorithm, jwt));
    }

    @Test
    void validate_doesNotThrow() throws JWTCreationException {
        JWT jwt = new JWT.Builder(algorithm).build();

        assertDoesNotThrow((Executable) jwt::validate);
    }

    @Test
    void sign_doesNotThrow() {
        assertDoesNotThrow(() -> new JWT.Builder(algorithm).sign());
    }

    @Test
    void signWithCustomPayload_doesNotThrow() {
        Map<String, String> payload = new HashMap<>();
        payload.put("custom-payload", "custom-payload-value");

        assertDoesNotThrow(() -> new JWT.Builder(algorithm).sign(payload));
    }

    @Test
    void sign() throws JWTCreationException {
        String jwt = new JWT.Builder(algorithm).sign();
        String expected = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.nx2GHSOLOGjofcETRXDMFQfkhN3YB-B5WMieLPkIM0MazzxtHN0YpuV5OMyQvx3r";

        assertThat(jwt, is(expected));
    }

    @Test
    void sign_jwtHasThreeSegments() throws JWTCreationException {
        String jwt = new JWT.Builder(algorithm).sign();
        int expected = 3;

        assertThat(jwt.split("\\.").length, is(expected));
    }
}