package dev.krypt04mcg.util;

import java.util.HexFormat;

public final class Hex {
    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private Hex() {}

    /**
     * Encodes the supplied value into the representation used by the hexadecimal encoding.
     *
     * @param bytes the bytes supplied to this operation
     * @return the result described above
     */
    public static String encode(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
