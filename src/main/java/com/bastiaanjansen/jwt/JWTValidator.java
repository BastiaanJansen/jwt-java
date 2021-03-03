package com.bastiaanjansen.jwt;

import com.bastiaanjansen.jwt.Exceptions.JWTValidationException;

/**
 * Interface which should be implemented by JWT validators.
 *
 * @author Bastiaan Jansen
 */
public interface JWTValidator {
    void validate(JWT jwt) throws JWTValidationException;
}
