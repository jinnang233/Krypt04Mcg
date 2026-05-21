package dev.obscuralink.model;

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
