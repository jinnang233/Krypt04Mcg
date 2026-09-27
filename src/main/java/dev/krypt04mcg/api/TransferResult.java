package dev.krypt04mcg.api;

import java.util.UUID;

/** DELIVERED means the remote receiver returned normally, not that it persisted the data. */
public record TransferResult(UUID transferId, Status status) {
    public enum Status { DELIVERED, REJECTED, TIMEOUT, BACKPRESSURE, DISABLED, DISCONNECTED, FAILED }
}
