package dev.obscuralink.model;

import java.time.Instant;

public record SessionRecord(
        String peer,
        String peerFingerprint,
        String sessionId,
        Instant createdAt,
        Instant lastUsedAt,
        String secret
) {
}
