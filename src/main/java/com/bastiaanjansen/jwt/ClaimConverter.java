package com.bastiaanjansen.jwt;

public interface ClaimConverter<T> {
    T convert(Object value);
}
