package dev.krypt04mcg.util;

import java.util.HexFormat;

public final class Hex {
    private Hex() {}

    public static String encode(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
