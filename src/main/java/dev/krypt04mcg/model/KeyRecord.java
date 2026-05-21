package dev.krypt04mcg.model;

import java.time.Instant;

public record KeyRecord(
        String algorithm,
        String owner,
        String uuid,
        String fingerprint,
        Instant createdAt,
        String keyData
) {
}
