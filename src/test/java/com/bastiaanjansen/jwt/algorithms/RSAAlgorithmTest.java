package com.bastiaanjansen.jwt.algorithms;

import com.bastiaanjansen.jwt.exceptions.JWTSignException;
import com.bastiaanjansen.jwt.exceptions.JWTValidationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class RSAAlgorithmTest {

    private Algorithm algorithm;

    @BeforeEach
    void setUp() {
        assertDoesNotThrow(() -> {
            String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm5PpsWJJvL3W+N0wiLniRbbrKx5qhxob/1hEfEzCOQLwl8pbO5UiuTE7nhdvHyCmQhAexpKIL0PRpKwHEWNN/KOxAZ5xdSIZU6W44Inq/hkK5ugbCViV4ONnpz+I1XoDNAi4ITJVpIPyqu2r4C4BTAZnozca8fe7p6VYzECnP3OZT+ELota4TRy3G5W6WIFayftGuvx0dncJOgy6SUaNuUBs2t9KXFHmxfYCz78WLq3QWDz21f1siqib+qHAdH5aNlPAkpqyP2hPLoc8VHKKs+Eb0QlkpW9ZABoybrHCWnPI1C4mdLMQ4MWqEgKKWvqrjDZDBfRfk6U/VUDuneQ9ZwIDAQAB";
            String privateKeyContent = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbk+mxYkm8vdb43TCIueJFtusrHmqHGhv/WER8TMI5AvCXyls7lSK5MTueF28fIKZCEB7GkogvQ9GkrAcRY038o7EBnnF1IhlTpbjgier+GQrm6BsJWJXg42enP4jVegM0CLghMlWkg/Kq7avgLgFMBmejNxrx97unpVjMQKc/c5lP4Qui1rhNHLcblbpYgVrJ+0a6/HR2dwk6DLpJRo25QGza30pcUebF9gLPvxYurdBYPPbV/WyKqJv6ocB0flo2U8CSmrI/aE8uhzxUcoqz4RvRCWSlb1kAGjJuscJac8jULiZ0sxDgxaoSAopa+quMNkMF9F+TpT9VQO6d5D1nAgMBAAECggEATT58SiktyTtMb9WKkmgQc2KlkowQgjGxcu9FWZ3W1O2jvQmokIW0btSF8DFcZ80THzvXu+nnGeiHP0Z2X+i5QNWZPd+IH4slngVrLHjtpumSIyFcwyArkjP2M/D0pGFnE7+8hCb0pLEqnDlTHARben63mC70/uxsTIlo9EipgXPCOBDAd/QsE3dhlO4SbEmCJMQR6eV1B8an+40ZbhQCG8IO832jDiDYabS5tyOPgU2ahG5UhzqsfPFQBlgJ2ePPyXXYaQlS1Gj8OD3ISJbCSxiitejbKjSaGsjoBv+81lkd3vqOYSZQDMf02rSRwp57mFfZ3G7Yk9lS+Q8abmUsyQKBgQDUtzLp3O+1363sT8lAjO9zWEXAqWT38mNaBqjR5c3Kv18xzm9LjTd9GfEgYgFmN6fkr1I85ZI35wR6pKjjJwUVci6615N2ghhTrcw9f8/zD/IejVPmYYIUdfRQ9FTlvM/RhDRCiyd1k7xQ/uGfy+Swu4bSzypzHUYeVQ6Xv5c/YwKBgQC7PEjjkzcLjn0EJcgnW11Md+Yrvg9NBKJO2JdMXfwRhN2NDAobbshJqaZeffgrTfU8KuGLmGNPE7UFnxOGnIVdDQwvjhde4LWuL/R6n10zu3tCmqvxBx7yzSO1+Ldi5bT9VI04x/gnGPQn489p0GBNWrN3AmC+RFXOridoVItTLQKBgBu3HvgfpFADK+sdXjB97HkP6E65A4HW4CELuxVWJuEi3ClmJ1QluzQenC9G9b22xLZkLYfntYx5GjlMmQC3xc7MiNApZHpNaxQEEhd1PsgBrN9UNLlQvR0jXUjq/ODOIBnBavm8ndCRBjlbbFRgwZRRariu624CQ2+ST4twGCnXAoGBAKvajGhdgiOYWEULTKhbIsqCLoCtxSuC+lr2UACnLysBUb0ZdNlzGGEMVwjaBIPy3QmprjVL3LMDOp77QJfIaFxdEnc/q1HJXNiRaYt3ZLuL9HnQr8reJ1jiU0m+DMy4XCQ9jBW27Z0tOUS3w3Oy8AFwI9MzGoro+/1lOgR3vR3NAoGAdmP0aPZfFHM6mdtkKVmNjPM8BTYhok+pEBzntNosUGqIT2u+TPFDV8aTYEti6mIrMVTO1mHRoqi9VL0WDHRT3IqTn3JE+KR2fUlMSE/PqW8MJ+70EhelgJj+bL6iyecnPqdquES57DYoFkdvqtz0qNL2gdzK5ay55YWgYbk0szw=";

            KeyFactory kf = KeyFactory.getInstance("RSA");

            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
            RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            algorithm = Algorithm.RSA512(keyPair);
        });
    }

    @AfterEach
    void tearDown() {
        this.algorithm = null;
    }

    @Test
    void sign_doesNotThrow() {
        assertDoesNotThrow(() -> algorithm.sign("data".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void sign() throws JWTSignException {
        byte[] signed = algorithm.sign("data".getBytes(StandardCharsets.UTF_8));
        String signedBase64URLEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signed);
        String expected = "QdJrTBFl4oQ0-Q8N14ZU_pXH0AZwpXS13c6W6XBlFw8WyKDjJ9dbwlMjYN9iparakh4WpkBTVHlfN4l9NcZaIipBcQZtgf6ZD3GJ5OfL2ZYVWdgBQKreDBS6frMrukC8aUZ3dckSWlYmC2R2OIdOZ_Dv37LEcr1boYGVCc9IokgnkhgcxTLm22RwcgF3-qiizgi0aSQy-p30YyKSza1NV6Sh_mJazVUhP2RND94bEZVL6bUVLS7g7W2YENDEjoHNIkKezVJ73Ek_LDaRA-DquiXeVpFuLJork7POVE3zv6Gzvbr196-GezLxw5QKi533TOpR4sXQP3sR6tOVFw3XxQ";

        assertThat(signedBase64URLEncoded, is(expected));
    }

    @Test
    void signWithString_doesNotThrow() {
        assertDoesNotThrow(() -> algorithm.sign("data"));
    }

    @Test
    void signWithString() throws JWTSignException {
        byte[] signed = algorithm.sign("data");
        String signedBase64URLEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signed);
        String expected = "QdJrTBFl4oQ0-Q8N14ZU_pXH0AZwpXS13c6W6XBlFw8WyKDjJ9dbwlMjYN9iparakh4WpkBTVHlfN4l9NcZaIipBcQZtgf6ZD3GJ5OfL2ZYVWdgBQKreDBS6frMrukC8aUZ3dckSWlYmC2R2OIdOZ_Dv37LEcr1boYGVCc9IokgnkhgcxTLm22RwcgF3-qiizgi0aSQy-p30YyKSza1NV6Sh_mJazVUhP2RND94bEZVL6bUVLS7g7W2YENDEjoHNIkKezVJ73Ek_LDaRA-DquiXeVpFuLJork7POVE3zv6Gzvbr196-GezLxw5QKi533TOpR4sXQP3sR6tOVFw3XxQ";

        assertThat(signedBase64URLEncoded, is(expected));
    }

    @Test
    void verify_doesNotThrow() {
        assertDoesNotThrow(() -> {
            algorithm.verify("data".getBytes(StandardCharsets.UTF_8), Base64.getUrlDecoder().decode("QdJrTBFl4oQ0-Q8N14ZU_pXH0AZwpXS13c6W6XBlFw8WyKDjJ9dbwlMjYN9iparakh4WpkBTVHlfN4l9NcZaIipBcQZtgf6ZD3GJ5OfL2ZYVWdgBQKreDBS6frMrukC8aUZ3dckSWlYmC2R2OIdOZ_Dv37LEcr1boYGVCc9IokgnkhgcxTLm22RwcgF3-qiizgi0aSQy-p30YyKSza1NV6Sh_mJazVUhP2RND94bEZVL6bUVLS7g7W2YENDEjoHNIkKezVJ73Ek_LDaRA-DquiXeVpFuLJork7POVE3zv6Gzvbr196-GezLxw5QKi533TOpR4sXQP3sR6tOVFw3XxQ"));
        });
    }

    @Test
    void verifyExpectedIsCorrect() throws JWTValidationException {
        boolean isValid = algorithm.verify("data".getBytes(StandardCharsets.UTF_8), Base64.getUrlDecoder().decode("QdJrTBFl4oQ0-Q8N14ZU_pXH0AZwpXS13c6W6XBlFw8WyKDjJ9dbwlMjYN9iparakh4WpkBTVHlfN4l9NcZaIipBcQZtgf6ZD3GJ5OfL2ZYVWdgBQKreDBS6frMrukC8aUZ3dckSWlYmC2R2OIdOZ_Dv37LEcr1boYGVCc9IokgnkhgcxTLm22RwcgF3-qiizgi0aSQy-p30YyKSza1NV6Sh_mJazVUhP2RND94bEZVL6bUVLS7g7W2YENDEjoHNIkKezVJ73Ek_LDaRA-DquiXeVpFuLJork7POVE3zv6Gzvbr196-GezLxw5QKi533TOpR4sXQP3sR6tOVFw3XxQ"));

        assertThat(isValid, is(true));
    }

    @Test
    void verifyExpectedIsIncorrect() throws JWTValidationException {
        boolean isValid = algorithm.verify("data".getBytes(StandardCharsets.UTF_8), Base64.getUrlDecoder().decode("QdJrTBFl4oQ0-Q8N14ZU_pXH0AZwpXS13c6W6XBlFw8WyKDjJ9dbwlMjYN9iparakh4WpkBTVHlfN4l9NcZaIipBcQZtgf6ZD3GJ5OfL2ZYVWdgBQKreDBS6frMrukC8aUZ3dckSWlYmC2R2OIdOZ_Dv37LEcr1boYGVCc9IokgnkhgcxTLm22RwcgF3-qiizgi0aSQy-p30YyKSza1NV6Sh_mJazVUhP2RND94bEZVL6bUVLS7g7W2YENDEjoHNIkKezVJ73Ek_LDaRA-DquiXeVpFuLJork7POVE3zv6Gzvbr196-GezLxw5QKi533TOpR4sXQP3sR6tOVFw3Xxs"));

        assertThat(isValid, is(false));
    }
}