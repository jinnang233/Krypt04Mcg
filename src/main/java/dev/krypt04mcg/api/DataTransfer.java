package dev.krypt04mcg.api;

import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.function.Consumer;

/** Read-only transfer handle. Observers cannot forge completion of the transport's future. */
public final class DataTransfer {
    private final UUID transferId;
    private final CompletionStage<TransferResult> completion;

    /** Internal transport bridge. */
    public DataTransfer(UUID transferId, CompletionStage<TransferResult> completion) {
        this.transferId = transferId;
        this.completion = completion.toCompletableFuture().minimalCompletionStage();
    }

    public UUID transferId() { return transferId; }
    public CompletionStage<TransferResult> completion() { return completion; }

    /** Runs on completion, or immediately on the caller if already complete. Never block the client thread. */
    public DataTransfer whenComplete(Consumer<TransferResult> receiver) {
        completion.thenAccept(receiver);
        return this;
    }
}
