package dev.obscuralink.service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.obscuralink.crypto.CryptoException;
import dev.obscuralink.crypto.CryptoService;
import dev.obscuralink.model.KeyRecord;
import dev.obscuralink.model.LocalKeyMaterial;
import dev.obscuralink.model.PublicIdentity;
import dev.obscuralink.util.Base64Url;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public final class KeyStoreService {
    private final Path root;
    private final Path keysDir;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private final CryptoService cryptoService;
    private LocalKeyMaterial local;

    public KeyStoreService(Path root, CryptoService cryptoService) {
        this.root = root;
        this.keysDir = root.resolve("keys");
        this.cryptoService = cryptoService;
    }

    public void init(String owner, String uuid) throws IOException, CryptoException {
        Files.createDirectories(keysDir.resolve("private"));
        Files.createDirectories(keysDir.resolve("public"));
        Files.createDirectories(root.resolve("sessions"));
        Files.createDirectories(root.resolve("cache"));
        Path localFile = keysDir.resolve("private").resolve("local.json");
        if (Files.exists(localFile)) {
            local = read(localFile, LocalKeyMaterial.class);
            return;
        }
        String stableUuid = uuid == null || uuid.isBlank() ? UUID.randomUUID().toString() : uuid;
        local = cryptoService.generateLocalKeys(owner, stableUuid);
        write(localFile, local);
        exportOwnPublic();
    }

    public LocalKeyMaterial local() {
        if (local == null) {
            throw new IllegalStateException("Key store has not been initialized");
        }
        return local;
    }

    public PublicIdentity ownPublicIdentity() {
        LocalKeyMaterial material = local();
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }

    public String exportOwnPublic() throws IOException {
        PublicIdentity identity = ownPublicIdentity();
        String json = gson.toJson(identity);
        Files.writeString(keysDir.resolve("public").resolve("self-public.json"), json, StandardCharsets.UTF_8);
        return Base64Url.encode(json.getBytes(StandardCharsets.UTF_8));
    }

    public PublicIdentity importPublicIdentity(String player, String dataOrFile) throws IOException {
        String json;
        Path maybeFile = Path.of(dataOrFile);
        if (Files.exists(maybeFile)) {
            json = Files.readString(maybeFile, StandardCharsets.UTF_8);
        } else {
            json = new String(Base64Url.decode(dataOrFile), StandardCharsets.UTF_8);
        }
        PublicIdentity incoming = gson.fromJson(json, PublicIdentity.class);
        if (incoming == null || incoming.kemPublicKey() == null || incoming.signaturePublicKey() == null) {
            throw new IOException("Imported public key data is incomplete");
        }
        String normalized = normalize(player);
        Path path = keysDir.resolve("public").resolve(normalized + ".json");
        if (Files.exists(path)) {
            PublicIdentity existing = read(path, PublicIdentity.class);
            if (!existing.kemPublicKey().fingerprint().equals(incoming.kemPublicKey().fingerprint())
                    || !existing.signaturePublicKey().fingerprint().equals(incoming.signaturePublicKey().fingerprint())) {
                throw new IOException("TOFU violation: public key for " + player + " changed; refusing to overwrite");
            }
            return existing;
        }
        write(path, incoming);
        return incoming;
    }

    public Optional<PublicIdentity> findPublicIdentity(String player) throws IOException {
        Path path = keysDir.resolve("public").resolve(normalize(player) + ".json");
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        return Optional.of(read(path, PublicIdentity.class));
    }

    public List<PublicIdentity> listPublicIdentities() throws IOException {
        List<PublicIdentity> result = new ArrayList<>();
        if (!Files.exists(keysDir.resolve("public"))) {
            return result;
        }
        try (var stream = Files.list(keysDir.resolve("public"))) {
            for (Path path : stream.filter(p -> p.toString().endsWith(".json")).toList()) {
                result.add(read(path, PublicIdentity.class));
            }
        }
        return result;
    }

    public KeyRecord rebuildPublicRecord(String algorithm, String owner, String uuid, String keyData) throws CryptoException {
        return cryptoService.keyRecord(algorithm, owner, uuid, Instant.now(), Base64Url.decode(keyData));
    }

    private <T> T read(Path path, Class<T> type) throws IOException {
        return gson.fromJson(Files.readString(path, StandardCharsets.UTF_8), type);
    }

    private void write(Path path, Object value) throws IOException {
        Files.writeString(path, gson.toJson(value), StandardCharsets.UTF_8);
    }

    private static String normalize(String player) {
        return player.toLowerCase().replaceAll("[^a-z0-9_.-]", "_");
    }
}
