package dev.krypt04mcg.service;

import com.google.gson.Gson;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Arrays;

public final class SessionService {
    private final Path sessionsDir;
    private final SecureRandom random = new SecureRandom();
    private final Gson gson = JsonSupport.prettyGson();
    private final SensitiveFileStore sensitiveFiles;

    public SessionService(Path root) {
        this.sessionsDir = root.resolve("sessions");
        this.sensitiveFiles = new SensitiveFileStore(root);
    }

    public synchronized void migrateLegacyFiles() throws IOException {
        if (!Files.isDirectory(sessionsDir)) {
            return;
        }
        try (var stream = Files.list(sessionsDir)) {
            for (Path path : stream.filter(candidate -> candidate.toString().endsWith(".json")).toList()) {
                if (!SensitiveFileStore.isEncrypted(path)) {
                    SessionRecord record = read(path);
                    validate(record);
                    save(record);
                }
            }
        }
    }

    public SessionRecord createLocalSession(String peer, String peerFingerprint) throws IOException {
        SessionRecord record = newSession(peer, peerFingerprint);
        save(record);
        return record;
    }

    public SessionRecord newSession(String peer, String peerFingerprint) {
        byte[] id = new byte[16];
        random.nextBytes(id);
        try {
            return newSession(peer, peerFingerprint, Base64Url.encode(id));
        } finally {
            Arrays.fill(id, (byte) 0);
        }
    }

    public SessionRecord newSession(String peer, String peerFingerprint, String sessionId) {
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        try {
            return new SessionRecord(peer, peerFingerprint, sessionId, Instant.now(), Instant.now(),
                    Base64Url.encode(secret), 0, 0L, 0L, 0L);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    public SessionRecord acceptRemoteSession(String peer, String peerFingerprint, String sessionId, String secret)
            throws IOException {
        SessionRecord record = new SessionRecord(peer, peerFingerprint, sessionId, Instant.now(), Instant.now(),
                secret, 0, 0L, 0L, 0L);
        save(record);
        return record;
    }

    public synchronized Optional<SessionRecord> find(String peer) throws IOException {
        Path path = pathFor(peer);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        SessionRecord record = read(path);
        validate(record);
        if (!SensitiveFileStore.isEncrypted(path)) {
            save(record);
        }
        return Optional.of(record);
    }

    public synchronized void save(SessionRecord record) throws IOException {
        validate(record);
        sensitiveFiles.writeString(pathFor(record.peer()), gson.toJson(record));
    }

    public List<SessionRecord> list() throws IOException {
        if (!Files.exists(sessionsDir)) {
            return List.of();
        }
        try (var stream = Files.list(sessionsDir)) {
            return stream.filter(path -> path.toString().endsWith(".json"))
                    .map(path -> {
                        try {
                            SessionRecord record = read(path);
                            validate(record);
                            if (!SensitiveFileStore.isEncrypted(path)) {
                                save(record);
                            }
                            return record;
                        } catch (IOException e) {
                            throw new IllegalStateException("Unable to read session " + path, e);
                        }
                    })
                    .toList();
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof IOException ioException) {
                throw ioException;
            }
            throw e;
        }
    }

    public synchronized void clear(String peer) throws IOException {
        Files.deleteIfExists(pathFor(peer));
    }

    public synchronized void recordSentMessage(String peer, long expectedSequence, long bytes) throws IOException {
        SessionRecord session = find(peer)
                .orElseThrow(() -> new IOException("No active session for " + peer));
        if (session.nextSendSequence() != expectedSequence) {
            throw new IOException("Session send sequence changed for " + peer);
        }
        save(new SessionRecord(session.peer(), session.peerFingerprint(), session.sessionId(), session.createdAt(),
                Instant.now(), session.secret(), session.messageCount() + 1, session.bytesUsed() + Math.max(0, bytes),
                expectedSequence + 1, session.nextReceiveSequence(), session.localFingerprint(),
                session.nextApiSendSequence(), session.nextApiReceiveSequence(), session.nextApiControlSendSequence(),
                session.nextApiControlReceiveSequence(), session.apiMessageCount(), session.apiBytesUsed(),
                session.apiReceiveWindow(), session.apiControlReceiveWindow()));
    }

    public synchronized void recordReceivedMessage(String peer, String sessionId, long sequence, long bytes)
            throws IOException {
        SessionRecord session = find(peer)
                .orElseThrow(() -> new IOException("No active session for " + peer));
        if (!session.sessionId().equals(sessionId) || session.nextReceiveSequence() != sequence) {
            throw new IOException("Session epoch or receive sequence mismatch for " + peer);
        }
        save(new SessionRecord(session.peer(), session.peerFingerprint(), session.sessionId(), session.createdAt(),
                Instant.now(), session.secret(), session.messageCount() + 1, session.bytesUsed() + Math.max(0, bytes),
                session.nextSendSequence(), sequence + 1, session.localFingerprint(),
                session.nextApiSendSequence(), session.nextApiReceiveSequence(), session.nextApiControlSendSequence(),
                session.nextApiControlReceiveSequence(), session.apiMessageCount(), session.apiBytesUsed(),
                session.apiReceiveWindow(), session.apiControlReceiveWindow()));
    }

    /** Reserve and persist before encryption. Gaps are safe; a failed send never reuses its sequence. */
    public synchronized long reserveApiSend(String peer, String sessionId, boolean control, long bytes) throws IOException {
        SessionRecord session = requireEpoch(peer, sessionId);
        long next = control ? session.nextApiControlSendSequence() : session.nextApiSendSequence();
        if (next >= (Long.MAX_VALUE - 1) / 2) throw new IOException("API sequence exhausted");
        saveApiCounters(session, control ? session.nextApiSendSequence() : next + 1, session.nextApiReceiveSequence(),
                control ? next + 1 : session.nextApiControlSendSequence(), session.nextApiControlReceiveSequence(), control, bytes);
        return next * 2 + (control ? 1 : 0);
    }

    /** DATA and receipts have independent monotonic sequences, encoded in even/odd wire numbers. */
    public synchronized void recordApiReceived(String peer, String sessionId, long sequence, boolean control, long bytes) throws IOException {
        SessionRecord session = requireEpoch(peer, sessionId);
        long next = control ? session.nextApiControlReceiveSequence() : session.nextApiReceiveSequence();
        if (sequence < 0 || sequence == Long.MAX_VALUE || (sequence & 1) != (control ? 1 : 0))
            throw new IOException("Repeated or invalid API sequence");
        Long storedWindow = control ? session.apiControlReceiveWindow() : session.apiReceiveWindow();
        long window = storedWindow == null ? legacyWindow(next) : storedWindow;
        long index = sequence / 2;
        long updatedNext = next;
        if (index >= next) {
            long shift = index - next + 1;
            window = shift >= Long.SIZE ? 1L : (window << shift) | 1L;
            updatedNext = index + 1;
        } else {
            long distance = next - 1 - index;
            if (distance >= Long.SIZE || (window & (1L << distance)) != 0)
                throw new IOException("Repeated or invalid API sequence");
            window |= 1L << distance;
        }
        saveApiCounters(session, session.nextApiSendSequence(), control ? session.nextApiReceiveSequence() : updatedNext,
                session.nextApiControlSendSequence(), control ? updatedNext : session.nextApiControlReceiveSequence(),
                control ? session.apiReceiveWindow() : window,
                control ? window : session.apiControlReceiveWindow(), control, bytes);
    }

    private SessionRecord requireEpoch(String peer, String id) throws IOException {
        SessionRecord session = find(peer).orElseThrow(() -> new IOException("Missing session"));
        if (!session.sessionId().equals(id)) throw new IOException("Session changed");
        return session;
    }

    private void saveApiCounters(SessionRecord s, long send, long receive, long controlSend, long controlReceive,
                                  boolean control, long bytes) throws IOException {
        saveApiCounters(s, send, receive, controlSend, controlReceive, s.apiReceiveWindow(),
                s.apiControlReceiveWindow(), control, bytes);
    }

    private void saveApiCounters(SessionRecord s, long send, long receive, long controlSend, long controlReceive,
                                 Long receiveWindow, Long controlReceiveWindow, boolean control, long bytes) throws IOException {
        save(new SessionRecord(s.peer(), s.peerFingerprint(), s.sessionId(), s.createdAt(), Instant.now(), s.secret(),
                s.messageCount(), s.bytesUsed(),
                s.nextSendSequence(), s.nextReceiveSequence(), s.localFingerprint(), send, receive, controlSend, controlReceive,
                control ? s.apiMessageCount() : Math.addExact(s.apiMessageCount(), 1),
                control ? s.apiBytesUsed() : Math.addExact(s.apiBytesUsed(), Math.max(0, bytes)),
                receiveWindow, controlReceiveWindow));
    }

    private static long legacyWindow(long next) {
        if (next <= 0) return 0;
        return next >= Long.SIZE ? -1L : (1L << next) - 1;
    }

    public boolean isExpired(SessionRecord session, int ttlMinutes, int maxMessages, long rotateAfterBytes) {
        Instant expiresAt = session.createdAt().plus(Duration.ofMinutes(ttlMinutes));
        return Instant.now().isAfter(expiresAt)
                || session.messageCount() >= maxMessages
                || session.bytesUsed() >= rotateAfterBytes;
    }

    public boolean isApiExpired(SessionRecord session, int ttlMinutes, int maxMessages, long rotateAfterBytes) {
        Instant expiresAt = session.createdAt().plus(Duration.ofMinutes(ttlMinutes));
        return Instant.now().isAfter(expiresAt)
                || session.apiMessageCount() >= maxMessages
                || session.apiBytesUsed() >= rotateAfterBytes;
    }

    private Path pathFor(String peer) {
        return sessionsDir.resolve(peer.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", "_") + ".json");
    }

    private SessionRecord read(Path path) throws IOException {
        return gson.fromJson(sensitiveFiles.readString(path), SessionRecord.class);
    }

    private static void validate(SessionRecord record) throws IOException {
        try {
            if (record == null || record.peer() == null || record.peer().isBlank()
                    || record.peerFingerprint() == null || record.peerFingerprint().isBlank()
                    || record.createdAt() == null || record.lastUsedAt() == null
                    || Base64Url.decode(record.sessionId()).length != 16
                    || Base64Url.decode(record.secret()).length != 32
                    || record.messageCount() < 0 || record.bytesUsed() < 0
                    || record.nextSendSequence() < 0 || record.nextReceiveSequence() < 0
                    || record.nextApiSendSequence() < 0 || record.nextApiReceiveSequence() < 0
                    || record.nextApiControlSendSequence() < 0 || record.nextApiControlReceiveSequence() < 0
                    || record.apiMessageCount() < 0 || record.apiBytesUsed() < 0) {
                throw new IOException("Session record is invalid");
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("Session record contains invalid key material", e);
        }
    }
}
