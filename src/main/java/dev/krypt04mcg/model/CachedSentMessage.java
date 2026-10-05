package dev.krypt04mcg.model;

import java.time.Instant;
import java.util.List;

public record CachedSentMessage(String messageId, String receiver, Instant createdAt, List<String> fragments,
                                String recipientFingerprint) {
    public CachedSentMessage(String messageId, String receiver, Instant createdAt, List<String> fragments) {
        this(messageId, receiver, createdAt, fragments, null);
    }
}
