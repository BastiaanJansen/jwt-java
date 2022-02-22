package com.bastiaanjansen.jwt;

public interface ClaimValidator {
    boolean validate(Object value);
}
