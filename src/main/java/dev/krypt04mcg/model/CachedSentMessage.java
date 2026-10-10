package dev.krypt04mcg.model;

import java.time.Instant;
import java.util.List;

public record CachedSentMessage(String messageId, String receiver, Instant createdAt, List<String> fragments,
                                String recipientFingerprint) {
    /**
     * Creates a cached sent message with the supplied dependencies and initial state.
     *
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param receiver the intended recipient associated with this operation
     * @param createdAt the created at supplied to this operation
     * @param fragments the fragments supplied to this operation
     */
    public CachedSentMessage(String messageId, String receiver, Instant createdAt, List<String> fragments) {
        this(messageId, receiver, createdAt, fragments, null);
    }
}
