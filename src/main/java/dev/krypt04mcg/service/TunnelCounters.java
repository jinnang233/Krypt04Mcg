package dev.krypt04mcg.service;

import dev.krypt04mcg.util.SensitiveFileStore;
import dev.krypt04mcg.util.SecureFiles;
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
        return update(path, -1);
    }

    /** Call only after OPEN authentication. TCP preserves OPEN order from the single sender worker. */
    public synchronized void accept(String peer, String sessionId, long lease) throws IOException {
        Path path = path(peer, sessionId, "receive");
        if (lease < 0) throw new IOException("Invalid tunnel lease");
        update(path, lease);
    }
    private long update(Path path, long received) throws IOException {
        // JVM serialization avoids OverlappingFileLockException; the OS lock covers other clients.
        synchronized (TunnelCounters.class) {
            SecureFiles.createPrivateDirectories(path.getParent());
            Path lockPath = path.resolveSibling(path.getFileName() + ".lock");
            SecureFiles.rejectLinks(lockPath);
            try (var channel = java.nio.channels.FileChannel.open(lockPath,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
                 var lock = channel.lock()) {
                long next = read(path);
                long value = received < 0 ? next : received;
                if (value < next || value == Long.MAX_VALUE) throw new IOException("Replayed or exhausted tunnel lease");
                files.writeStringDurable(path, Long.toString(value + 1));
                return value;
            }
        }
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
