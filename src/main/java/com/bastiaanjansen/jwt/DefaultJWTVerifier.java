package com.bastiaanjansen.jwt;

import java.time.LocalDate;

public class DefaultJWTVerifier implements JWTVerifier {

    private final JWT jwt;

    public DefaultJWTVerifier(JWT jwt) {
        this.jwt = jwt;
    }

    @Override
    public boolean verify() {
        if (jwt.getHeader().containsKey(Header.Registered.TYPE) && !jwt.getHeader().get(Header.Registered.TYPE).toString().equalsIgnoreCase("JWT"))
            return false;

        if (!jwt.getHeader().containsKey(Header.Registered.ALGORITHM))
            return false;

        if (jwt.getHeader().containsKey(Claim.Registered.EXPIRATION_TIME)) {
            Object payloadExpirationDate = jwt.getPayload().get(Claim.Registered.EXPIRATION_TIME);
            if (LocalDate.now().compareTo(LocalDate.parse(payloadExpirationDate.toString())) < 0)
                return false;
        }

        return jwt.getAlgorithm().verify(jwt);
    }
}
