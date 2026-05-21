package dev.krypt04mcg.model;

import java.time.Instant;
import java.util.List;

public record GroupRecord(String name, List<String> members, Instant createdAt) {
}
