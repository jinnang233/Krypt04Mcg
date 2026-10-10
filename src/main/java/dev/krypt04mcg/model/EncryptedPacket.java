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

    /**
     * Creates a encrypted packet with the supplied dependencies and initial state.
     *
     * @param protocolVersion the protocol version supplied to this operation
     * @param type the type supplied to this operation
     * @param flags the flags supplied to this operation
     * @param sender the sender or source associated with this operation
     * @param receiver the intended recipient associated with this operation
     * @param timestampMillis the timestamp millis supplied to this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param aadFragmentIndex the aad fragment index supplied to this operation
     * @param aadFragmentTotal the aad fragment total supplied to this operation
     * @param algorithms the algorithms supplied to this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @param kemCiphertext the kem ciphertext supplied to this operation
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @param signature the signature bytes or signature representation to verify
     */
    public EncryptedPacket(byte protocolVersion, PacketType type, byte flags, String sender, String receiver,
                           long timestampMillis, byte[] messageId, short aadFragmentIndex, short aadFragmentTotal,
                           AlgorithmSuite algorithms, byte[] nonce, byte[] kemCiphertext, byte[] ciphertext,
                           byte[] signature) {
        this(protocolVersion, type, flags, sender, receiver, timestampMillis, messageId, aadFragmentIndex,
                aadFragmentTotal, algorithms, nonce, kemCiphertext, ciphertext, signature, "", 0);
    }

    /**
     * Performs the signed operation for the encrypted packet.
     *
     * @return whether the condition or operation described above succeeds
     */
    public boolean signed() {
        return signature != null && signature.length > 0;
    }
}
