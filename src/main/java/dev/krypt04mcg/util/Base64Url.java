package dev.krypt04mcg.util;

import java.util.Base64;

public final class Base64Url {
    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private Base64Url() {
    }

    /**
     * Encodes the supplied value into the representation used by the Base64URL encoding.
     *
     * @param bytes the bytes supplied to this operation
     * @return the result described above
     */
    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Decodes the supplied input using the format expected by the Base64URL encoding.
     *
     * @param text the text supplied to this operation
     * @return the resulting array produced by this operation
     */
    public static byte[] decode(String text) {
        return Base64.getUrlDecoder().decode(text);
    }
}
