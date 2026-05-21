package dev.obscuralink.service;

import com.google.gson.Gson;
import dev.obscuralink.model.SessionRecord;
import dev.obscuralink.util.Base64Url;
import dev.obscuralink.util.JsonSupport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;

public final class SessionService {
    private final Path sessionsDir;
    private final SecureRandom random = new SecureRandom();
    private final Gson gson = JsonSupport.prettyGson();

    public SessionService(Path root) {
        this.sessionsDir = root.resolve("sessions");
    }

    public SessionRecord createLocalSession(String peer, String peerFingerprint) throws IOException {
        Files.createDirectories(sessionsDir);
        byte[] id = new byte[16];
        byte[] secret = new byte[32];
        random.nextBytes(id);
        random.nextBytes(secret);
        SessionRecord record = new SessionRecord(peer, peerFingerprint, Base64Url.encode(id), Instant.now(), Instant.now(),
                Base64Url.encode(secret));
        save(record);
        return record;
    }

    public Optional<SessionRecord> find(String peer) throws IOException {
        Path path = pathFor(peer);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        return Optional.of(gson.fromJson(Files.readString(path, StandardCharsets.UTF_8), SessionRecord.class));
    }

    public void save(SessionRecord record) throws IOException {
        Files.createDirectories(sessionsDir);
        Files.writeString(pathFor(record.peer()), gson.toJson(record), StandardCharsets.UTF_8);
    }

    private Path pathFor(String peer) {
        return sessionsDir.resolve(peer.toLowerCase().replaceAll("[^a-z0-9_.-]", "_") + ".json");
    }
}
