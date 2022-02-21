package com.bastiaanjansen.jwt;

@FunctionalInterface
public interface ClaimValidator {
    boolean validate(Object value);
}
