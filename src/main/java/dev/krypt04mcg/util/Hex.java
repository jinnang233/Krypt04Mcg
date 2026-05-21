package dev.krypt04mcg.util;

public final class Hex {
    private static final char[] ALPHABET = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            out[i * 2] = ALPHABET[value >>> 4];
            out[i * 2 + 1] = ALPHABET[value & 0x0f];
        }
        return new String(out);
    }
}
