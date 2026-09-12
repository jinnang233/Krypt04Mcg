package dev.krypt04mcg.model;

public record EncryptedPacket(
        byte protocolVersion,
        PacketType type,
        byte flags,
        String sender,
        String receiver,
        long timestampMillis,
        byte[] messageId,
        short aadFragmentIndex,
        short aadFragmentTotal,
        AlgorithmSuite algorithms,
        byte[] nonce,
        byte[] kemCiphertext,
        byte[] ciphertext,
        byte[] signature,
        String sessionId,
        long sequence
) {
    public static final byte LEGACY_VERSION = 1;
    public static final byte PREVIOUS_VERSION = 2;
    public static final byte COMPACT_VERSION = 3;
    public static final byte VERSION = 4;

    public EncryptedPacket(byte protocolVersion, PacketType type, byte flags, String sender, String receiver,
                           long timestampMillis, byte[] messageId, short aadFragmentIndex, short aadFragmentTotal,
                           AlgorithmSuite algorithms, byte[] nonce, byte[] kemCiphertext, byte[] ciphertext,
                           byte[] signature) {
        this(protocolVersion, type, flags, sender, receiver, timestampMillis, messageId, aadFragmentIndex,
                aadFragmentTotal, algorithms, nonce, kemCiphertext, ciphertext, signature, "", 0);
    }

    public boolean signed() {
        return signature != null && signature.length > 0;
    }
}
