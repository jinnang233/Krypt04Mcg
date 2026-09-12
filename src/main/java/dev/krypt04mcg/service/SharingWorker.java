package dev.krypt04mcg.service;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.*;

/** One running operation, no queued large envelopes, including while awaiting UI delivery. */
public final class SharingWorker implements AutoCloseable {
    private final AtomicBoolean busy = new AtomicBoolean();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(
            Thread.ofPlatform().daemon().name("krypt04mcg-sharing").factory());

    public boolean busy() { return busy.get(); }

    public <T> boolean submit(Callable<T> operation, Consumer<Runnable> dispatch, BiConsumer<T, Exception> completed) {
        if (!busy.compareAndSet(false, true)) return false;
        try {
            executor.execute(() -> {
                T value = null;
                Exception error = null;
                try { value = operation.call(); } catch (Exception e) { error = e; }
                T result = value;
                Exception failure = error;
                try {
                    dispatch.accept(() -> {
                        try { completed.accept(result, failure); } finally { busy.set(false); }
                    });
                } catch (RuntimeException e) { busy.set(false); }
            });
        } catch (RejectedExecutionException e) { busy.set(false); return false; }
        return true;
    }

    @Override public void close() { executor.shutdownNow(); }
}
