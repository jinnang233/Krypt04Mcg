package dev.obscuralink.util;

import java.util.Base64;

public final class Base64Url {
    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] decode(String text) {
        return Base64.getUrlDecoder().decode(text);
    }
}
