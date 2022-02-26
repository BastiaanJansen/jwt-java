package com.bastiaanjansen.jwt.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Class with utility functions for encoding and decoding base64 data
 *
 * @author Bastiaan Jansen
 */
public class Base64Utils {

    private Base64Utils() {}

    /**
     * Encode string to base64URL string
     *
     * @param data String to encode
     * @return Encoded String
     */
    public static String encodeBase64URL(String data) {
        return encodeBase64URL(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encode byte array to base64URL string
     *
     * @param data Byte array to encode
     * @return Encoded String
     */
    public static String encodeBase64URL(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Decode base64URL string
     *
     * @param encoded Base64URl encoded String
     * @return Decoded string
     */
    public static String decodeBase64URL(String encoded) {
        byte[] decoded = Base64.getUrlDecoder().decode(encoded);
        return new String(decoded);
    }

}
