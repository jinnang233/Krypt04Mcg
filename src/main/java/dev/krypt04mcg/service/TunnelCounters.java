package dev.krypt04mcg.service;

import dev.krypt04mcg.util.SensitiveFileStore;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Durable stream leases, independent of DataTransferService's replay window and usage limits. */
public final class TunnelCounters {
    private final Path root;
    private final SensitiveFileStore files;
    public TunnelCounters(Path root) { this.root = root; files = new SensitiveFileStore(root); }

    public synchronized long reserve(String peer, String sessionId) throws IOException {
        Path path = path(peer, sessionId, "send");
        long next = read(path);
        if (next == Long.MAX_VALUE) throw new IOException("Tunnel counter exhausted");
        files.writeString(path, Long.toString(next + 1));
        return next;
    }

    /** Call only after OPEN authentication. TCP preserves OPEN order from the single sender worker. */
    public synchronized void accept(String peer, String sessionId, long lease) throws IOException {
        Path path = path(peer, sessionId, "receive");
        if (lease < read(path) || lease == Long.MAX_VALUE) throw new IOException("Replayed tunnel OPEN");
        files.writeString(path, Long.toString(lease + 1));
    }
    private long read(Path path) throws IOException {
        if (!Files.exists(path)) return 0;
        try {
            long value = Long.parseLong(files.readString(path));
            if (value < 0) throw new NumberFormatException();
            return value;
        } catch (NumberFormatException e) { throw new IOException("Invalid tunnel counter", e); }
    }
    private Path path(String peer, String session, String direction) {
        if (!peer.matches("[A-Za-z0-9_]{1,16}") || !session.matches("[A-Za-z0-9_-]{22}"))
            throw new IllegalArgumentException("Invalid tunnel identity");
        return root.resolve("tunnel-counters").resolve(peer.toLowerCase(java.util.Locale.ROOT)
                + "-" + session + "-" + direction + ".dat");
    }
}
