package com.bastiaanjansen.jwt;

public interface ClaimParser<T> {
    T parse(Object value);
}
