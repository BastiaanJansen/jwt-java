package com.bastiaanjansen.jwt;

import java.util.HashMap;
import java.util.Map;

public class Header extends HashMap<String, Object> {
    public static class Registered {
        static String TYPE = "typ";
        static String CONTENT_TYPE = "cty";
        static String ALGORITHM = "alg";
    }

    public Header() {
        setType("JWT");
    }

    public Header(Map<String, Object> map) {
        this();
        putAll(map);
    }

    public void setType(String type) {
        put(Registered.TYPE, type);
    }

    public Object getType() {
        return get(Registered.TYPE);
    }

    public void setContentType(String value) {
        put(Registered.CONTENT_TYPE, value);
    }

    public Object getContentType() {
        return get(Registered.CONTENT_TYPE);
    }

    public void setAlgorithm(String algorithm) {
        put(Registered.ALGORITHM, algorithm);
    }
}
