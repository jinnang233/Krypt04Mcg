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

    /**
     * Creates a file receive task with the supplied dependencies and initial state.
     *
     * @param socket the encrypted or TCP socket participating in the operation
     */
    public FileReceiveTask(KryptSocket socket) { this(socket, System::nanoTime); }

    /**
     * Creates a file receive task with the supplied dependencies and initial state.
     *
     * @param socket the encrypted or TCP socket participating in the operation
     * @param clock the time source used for deadline or expiry checks
     */
    FileReceiveTask(KryptSocket socket, LongSupplier clock) {
        this.socket = Objects.requireNonNull(socket);
        this.clock = Objects.requireNonNull(clock);
        this.started = clock.getAsLong();
    }

    /**
     * Reads the bounded built-in file format through the authenticated socket and rechecks the original
     * fixed completion deadline before returning data. The format reader requires complete content and
     * EOF; malformed, failed or late input fails the socket and retires the task.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
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

    /**
     * Fails an unfinished file receive after its original monotonic total-duration deadline. Receiving
     * more bytes does not extend the lifetime, so a slow sender cannot hold the shared sharing worker
     * indefinitely.
     *
     * @return whether the condition or operation described above succeeds
     */
    public synchronized boolean expire() {
        if (finished || clock.getAsLong() - started < MAX_DURATION_NANOS) return false;
        socket.fail("File receive deadline exceeded");
        return true;
    }

    /**
     * Fails the associated incoming file stream so worker reads terminate and retained task resources can
     * be released.
     */
    public synchronized void cancel() { socket.fail("File receive cancelled"); }
}
