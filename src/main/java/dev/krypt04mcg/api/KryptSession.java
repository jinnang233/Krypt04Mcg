package dev.krypt04mcg.api;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;

/** A client-thread handle for one peer and session epoch. It never exposes the session secret. */
public final class KryptSession implements AutoCloseable {
    private final String peer;
    private final CompletableFuture<String> readiness;
    private final BiConsumer<String, byte[]> sender;
    private final Runnable closer;
    private final BooleanSupplier valid;
    private boolean closed;

    /**
     * Creates a krypt session with the supplied dependencies and initial state.
     *
     * @param peer the peer identifier associated with this operation
     * @param readiness the readiness supplied to this operation
     * @param sender the sender or source associated with this operation
     * @param closer the closer supplied to this operation
     * @param valid the valid supplied to this operation
     */
    public KryptSession(String peer, CompletionStage<String> readiness,
                        BiConsumer<String, byte[]> sender, Runnable closer, BooleanSupplier valid) {
        this.peer = peer;
        this.readiness = readiness.toCompletableFuture().minimalCompletionStage().toCompletableFuture();
        this.sender = sender;
        this.closer = closer;
        this.valid = valid;
    }

    /**
     * Returns the peer value used by the peer API session handle.
     *
     * @return the result described above
     */
    public String peer() { return peer; }
    /**
     * Reports whether ready holds for the peer API session handle.
     *
     * @return whether the condition or operation described above succeeds
     */
    public boolean isReady() { return !closed && valid.getAsBoolean() && readiness.isDone() && !readiness.isCompletedExceptionally(); }
    /**
     * Returns the session id value used by the peer API session handle.
     *
     * @return the result described above
     */
    public String sessionId() { return isReady() ? readiness.getNow(null) : null; }
    /**
     * Reads y from the input used by the peer API session handle.
     *
     * @return the result described above
     */
    public CompletionStage<KryptSession> ready() { return readiness.minimalCompletionStage().thenApply(id -> this); }
    /**
     * May be called before ready: stream writes wait in the bounded channel pool.
     *
     * @param channel the business or transport channel identifier
     * @param data the data supplied to this operation
     */
    public void send(String channel, byte[] data) {
        if (closed || !valid.getAsBoolean()) throw new IllegalStateException("Session is closed");
        sender.accept(channel, data);
    }
    /**
     * Closes this local handle and cancels its queued sends; chat and other peer sessions remain intact.
     */
    @Override public void close() { closer.run(); closed = true; }
}
