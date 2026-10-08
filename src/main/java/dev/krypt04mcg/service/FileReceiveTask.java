package dev.krypt04mcg.service;

import dev.krypt04mcg.api.KryptSocket;
import dev.krypt04mcg.protocol.FileStreamCodec;
import dev.krypt04mcg.protocol.FileStreamCodec.FileData;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.function.LongSupplier;

/** A file must finish, including authenticated EOF, within a fixed receive deadline. */
public final class FileReceiveTask {
    private static final long MAX_DURATION_NANOS = Duration.ofMinutes(2).toNanos();
    private final KryptSocket socket;
    private final LongSupplier clock;
    private final long started;
    private boolean finished;

    public FileReceiveTask(KryptSocket socket) { this(socket, System::nanoTime); }

    FileReceiveTask(KryptSocket socket, LongSupplier clock) {
        this.socket = Objects.requireNonNull(socket);
        this.clock = Objects.requireNonNull(clock);
        this.started = clock.getAsLong();
    }

    public FileData read() throws IOException {
        try {
            FileData data = FileStreamCodec.read(socket.getInputStream());
            synchronized (this) {
                expire();
                if (socket.isFailed()) throw new IOException("File receive cancelled or expired");
                finished = true;
            }
            return data;
        } catch (IOException error) {
            socket.fail("Invalid or expired file stream");
            throw error;
        } finally {
            synchronized (this) { finished = true; }
        }
    }

    /** Called on client ticks; cancelling the socket wakes a blocked file reader. */
    public synchronized boolean expire() {
        if (finished || clock.getAsLong() - started < MAX_DURATION_NANOS) return false;
        socket.fail("File receive deadline exceeded");
        return true;
    }

    public synchronized void cancel() { socket.fail("File receive cancelled"); }
}
