package com.bastiaanjansen.jwt.Utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Utils {

    public static String encodeBase64URL(String data) {
        return encodeBase64URL(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String encodeBase64URL(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static String decodeBase64URL(String encoded) {
        byte[] decoded = Base64.getUrlDecoder().decode(encoded);
        return new String(decoded);
    }

}
