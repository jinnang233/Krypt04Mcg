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
        long bytesUsed
) {
}
