package com.bastiaanjansen.jwt;

public class Claim {
    public static class Registered {
        static String ISSUER = "iss";
        static String SUBJECT = "sub";
        static String AUDIENCE = "aud";
        static String EXPIRATION_TIME = "exp";
        static String NOT_BEFORE = "nbf";
        static String ISSUED_AT = "iat";
        static String JWT_ID = "jti";
    }
}
