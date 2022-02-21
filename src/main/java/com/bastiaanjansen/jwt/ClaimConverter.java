package com.bastiaanjansen.jwt;

@FunctionalInterface
public interface ClaimConverter<T> {
    T convert(Object value);
}
