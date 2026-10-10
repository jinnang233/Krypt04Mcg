package dev.krypt04mcg.service;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.krypt04mcg.model.CachedSentMessage;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SecureFiles;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class SentMessageCacheService {
    private static final Type CACHE_TYPE = new TypeToken<Map<String, CachedSentMessage>>() {
    }.getType();
    private static final int MAX_CACHED_MESSAGES = 12;

    private final Path cacheFile;
    private final Gson gson = JsonSupport.prettyGson();

    /**
     * Creates a sent message cache service with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public SentMessageCacheService(Path root) {
        this.cacheFile = root.resolve("cache").resolve("sent-fragments.json");
    }

    /**
     * Performs the remember operation for the recipient-bound ciphertext resend cache.
     *
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param receiver the intended recipient associated with this operation
     * @param fragments the fragments supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void remember(String messageId, String receiver, List<String> fragments) throws IOException {
        remember(messageId, receiver, fragments, null);
    }

    /**
     * Performs the remember operation for the recipient-bound ciphertext resend cache.
     *
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param receiver the intended recipient associated with this operation
     * @param fragments the fragments supplied to this operation
     * @param recipientFingerprint the recipient fingerprint supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void remember(String messageId, String receiver, List<String> fragments,
                                      String recipientFingerprint) throws IOException {
        Map<String, CachedSentMessage> cache = readCache();
        cache.put(messageId, new CachedSentMessage(messageId, receiver, Instant.now(), List.copyOf(fragments),
                recipientFingerprint));
        trim(cache);
        SecureFiles.atomicWrite(cacheFile, gson.toJson(cache, CACHE_TYPE).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Performs the latest operation for the recipient-bound ciphertext resend cache.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized Optional<CachedSentMessage> latest() throws IOException {
        return readCache().values().stream()
                .max(Comparator.comparing(CachedSentMessage::createdAt));
    }

    /**
     * Looks up the requested entry in the recipient-bound ciphertext resend cache without creating a
     * replacement.
     *
     * @param messageId the message identifier used for correlation or key-derivation context
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized Optional<CachedSentMessage> find(String messageId) throws IOException {
        return Optional.ofNullable(readCache().get(messageId));
    }

    /**
     * Reads cache from the input used by the recipient-bound ciphertext resend cache.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private Map<String, CachedSentMessage> readCache() throws IOException {
        SecureFiles.rejectLinks(cacheFile);
        if (!Files.exists(cacheFile)) {
            return new LinkedHashMap<>();
        }
        SecureFiles.restrictToOwner(cacheFile, false);
        Map<String, CachedSentMessage> cache = gson.fromJson(Files.readString(cacheFile, StandardCharsets.UTF_8), CACHE_TYPE);
        return cache == null ? new LinkedHashMap<>() : new LinkedHashMap<>(cache);
    }

    /**
     * Performs the trim operation for the recipient-bound ciphertext resend cache.
     *
     * @param cache the cache supplied to this operation
     */
    private static void trim(Map<String, CachedSentMessage> cache) {
        while (cache.size() > MAX_CACHED_MESSAGES) {
            String oldest = cache.values().stream()
                    .min(Comparator.comparing(CachedSentMessage::createdAt))
                    .map(CachedSentMessage::messageId)
                    .orElse(null);
            if (oldest == null) {
                return;
            }
            cache.remove(oldest);
        }
    }
}
