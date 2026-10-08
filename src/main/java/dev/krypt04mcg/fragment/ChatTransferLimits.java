package dev.krypt04mcg.fragment;

/** Bounds for encrypted chat packets; raw API/file streams have separate limits. */
public final class ChatTransferLimits {
    public static final int MAX_PACKET_BYTES = 256 * 1024;
    public static final int MAX_ENCODED_PACKET_CHARS = (MAX_PACKET_BYTES * 4 + 2) / 3;
    public static final int MAX_FRAGMENTS = 2048;

    private ChatTransferLimits() {}
}
