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
    public SessionRecord(String peer, String peerFingerprint, String sessionId, Instant createdAt, Instant lastUsedAt,
                         String secret, int messageCount, long bytesUsed, long nextSendSequence, long nextReceiveSequence) {
        this(peer, peerFingerprint, sessionId, createdAt, lastUsedAt, secret, messageCount, bytesUsed,
                nextSendSequence, nextReceiveSequence, "", 0, 0, 0, 0);
    }

    public SessionRecord withLocalFingerprint(String fingerprint) {
        return new SessionRecord(peer, peerFingerprint, sessionId, createdAt, lastUsedAt, secret, messageCount, bytesUsed,
                nextSendSequence, nextReceiveSequence, fingerprint, nextApiSendSequence, nextApiReceiveSequence,
                nextApiControlSendSequence, nextApiControlReceiveSequence);
    }

    public SessionRecord(String peer, String peerFingerprint, String sessionId, Instant createdAt, Instant lastUsedAt,
                         String secret, int messageCount, long bytesUsed) {
        this(peer, peerFingerprint, sessionId, createdAt, lastUsedAt, secret, messageCount, bytesUsed, 0L, 0L);
    }
}
