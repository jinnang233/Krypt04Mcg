package dev.krypt04mcg.model;

import java.time.Instant;

public record SessionRecord(
        String peer,
        String peerFingerprint,
        String sessionId,
        Instant createdAt,
        Instant lastUsedAt,
        String secret,
        int messageCount,
        long bytesUsed,
        long nextSendSequence,
        long nextReceiveSequence,
        String localFingerprint,
        long nextApiSendSequence,
        long nextApiReceiveSequence,
        long nextApiControlSendSequence,
        long nextApiControlReceiveSequence
) {
    /**
     * Creates a session record with the supplied dependencies and initial state.
     *
     * @param peer the peer identifier associated with this operation
     * @param peerFingerprint the peer fingerprint supplied to this operation
     * @param sessionId the identifier of the expected session epoch
     * @param createdAt the created at supplied to this operation
     * @param lastUsedAt the last used at supplied to this operation
     * @param secret the shared secret used as key-derivation input
     * @param messageCount the message count supplied to this operation
     * @param bytesUsed the bytes used supplied to this operation
     * @param nextSendSequence the next send sequence supplied to this operation
     * @param nextReceiveSequence the next receive sequence supplied to this operation
     */
    public SessionRecord(String peer, String peerFingerprint, String sessionId, Instant createdAt, Instant lastUsedAt,
                         String secret, int messageCount, long bytesUsed, long nextSendSequence, long nextReceiveSequence) {
        this(peer, peerFingerprint, sessionId, createdAt, lastUsedAt, secret, messageCount, bytesUsed,
                nextSendSequence, nextReceiveSequence, "", 0, 0, 0, 0);
    }

    /**
     * Returns a value with the supplied local fingerprint while retaining the other recorded fields.
     *
     * @param fingerprint the fingerprint supplied to this operation
     * @return the result described above
     */
    public SessionRecord withLocalFingerprint(String fingerprint) {
        return new SessionRecord(peer, peerFingerprint, sessionId, createdAt, lastUsedAt, secret, messageCount, bytesUsed,
                nextSendSequence, nextReceiveSequence, fingerprint, nextApiSendSequence, nextApiReceiveSequence,
                nextApiControlSendSequence, nextApiControlReceiveSequence);
    }

    /**
     * Creates a session record with the supplied dependencies and initial state.
     *
     * @param peer the peer identifier associated with this operation
     * @param peerFingerprint the peer fingerprint supplied to this operation
     * @param sessionId the identifier of the expected session epoch
     * @param createdAt the created at supplied to this operation
     * @param lastUsedAt the last used at supplied to this operation
     * @param secret the shared secret used as key-derivation input
     * @param messageCount the message count supplied to this operation
     * @param bytesUsed the bytes used supplied to this operation
     */
    public SessionRecord(String peer, String peerFingerprint, String sessionId, Instant createdAt, Instant lastUsedAt,
                         String secret, int messageCount, long bytesUsed) {
        this(peer, peerFingerprint, sessionId, createdAt, lastUsedAt, secret, messageCount, bytesUsed, 0L, 0L);
    }
}
