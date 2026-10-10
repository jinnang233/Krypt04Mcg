package dev.krypt04mcg.service;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SecureFiles;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class DecryptionHistoryService {
    private static final Type HISTORY_TYPE = new TypeToken<Map<String, Instant>>() {
    }.getType();
    private static final String PACKET_PREFIX = "packet:";
    private static final String NONCE_PREFIX = "nonce:";
    private static final int MAX_REPLAY_ENTRIES_PER_PLAYER = 32_768;
    private static final Duration REPLAY_RETENTION = Duration.ofMinutes(65);

    private final Path historyFile;
    private final Gson gson = JsonSupport.prettyGson();

    /**
     * Creates a decryption history service with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public DecryptionHistoryService(Path root) {
        this.historyFile = root.resolve("cache").resolve("decryption-history.json");
    }

    /**
     * Performs the record success operation for the accepted-packet replay history.
     *
     * @param player the player supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void recordSuccess(String player) throws IOException {
        Map<String, Instant> history = readHistory();
        history.put(normalize(player), Instant.now());
        writeHistory(history);
    }

    /**
     * Performs the last success operation for the accepted-packet replay history.
     *
     * @param player the player supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized Optional<Instant> lastSuccess(String player) throws IOException {
        return Optional.ofNullable(readHistory().get(normalize(player)));
    }

    /**
     * Checks live peer-scoped message-ID and nonce replay entries after pruning expired history. Either
     * matching identifier is sufficient to reject reuse; the history is only meaningful after
     * authenticating the original accepted packet.
     *
     * @param player the player supplied to this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param nonce the nonce associated with this cryptographic operation
     * @return whether the condition or operation described above succeeds
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized boolean wasAcceptedPacket(String player, byte[] messageId, byte[] nonce) throws IOException {
        Map<String, Instant> history = readHistory();
        pruneExpiredReplayEntries(history, Instant.now());
        String normalized = normalize(player);
        return history.containsKey(PACKET_PREFIX + normalized + ":" + Hex.encode(messageId))
                || history.containsKey(NONCE_PREFIX + normalized + ":" + Hex.encode(nonce));
    }

    /**
     * Atomically checks peer-scoped message ID and nonce evidence, refuses duplicates or exhausted
     * per-player replay capacity, then persists both acceptance entries. Live evidence is not evicted
     * merely to admit another packet, preventing cache pressure from reviving still-valid replays.
     *
     * @param player the player supplied to this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param nonce the nonce associated with this cryptographic operation
     * @return whether the condition or operation described above succeeds
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized boolean recordAcceptedPacket(String player, byte[] messageId, byte[] nonce) throws IOException {
        Map<String, Instant> history = readHistory();
        String normalized = normalize(player);
        String packetKey = PACKET_PREFIX + normalized + ":" + Hex.encode(messageId);
        String nonceKey = NONCE_PREFIX + normalized + ":" + Hex.encode(nonce);
        Instant now = Instant.now();
        pruneExpiredReplayEntries(history, now);
        if (history.containsKey(packetKey) || history.containsKey(nonceKey)) {
            return false;
        }
        String packetPlayerPrefix = PACKET_PREFIX + normalized + ":";
        String noncePlayerPrefix = NONCE_PREFIX + normalized + ":";
        long playerEntries = history.keySet().stream()
                .filter(key -> key.startsWith(packetPlayerPrefix) || key.startsWith(noncePlayerPrefix)).count();
        if (playerEntries > MAX_REPLAY_ENTRIES_PER_PLAYER - 2) {
            return false;
        }
        history.put(packetKey, now);
        history.put(nonceKey, now);
        writeHistory(history);
        return true;
    }

    /**
     * Reads history from the input used by the accepted-packet replay history.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private Map<String, Instant> readHistory() throws IOException {
        SecureFiles.rejectLinks(historyFile);
        if (!Files.exists(historyFile)) {
            return new HashMap<>();
        }
        SecureFiles.restrictToOwner(historyFile, false);
        Map<String, Instant> history = gson.fromJson(Files.readString(historyFile, StandardCharsets.UTF_8), HISTORY_TYPE);
        return history == null ? new HashMap<>() : new HashMap<>(history);
    }

    /**
     * Persists decryption/replay history using its implemented private-file checks and atomic write path.
     * Callers must record only authenticated acceptance rather than unauthenticated fragment arrival.
     *
     * @param history the history supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void writeHistory(Map<String, Instant> history) throws IOException {
        SecureFiles.atomicWrite(historyFile, gson.toJson(history, HISTORY_TYPE).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Removes replay evidence only after its configured retention window. Expiry is independent of recent
     * duplicate traffic and must remain long enough for the accepted authenticated freshness window.
     *
     * @param history the history supplied to this operation
     * @param now the now supplied to this operation
     */
    private static void pruneExpiredReplayEntries(Map<String, Instant> history, Instant now) {
        Instant cutoff = now.minus(REPLAY_RETENTION);
        history.entrySet().removeIf(entry -> isReplayKey(entry.getKey()) && entry.getValue().isBefore(cutoff));
    }

    /**
     * Reports whether replay key holds for the accepted-packet replay history.
     *
     * @param key the cryptographic key material for this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean isReplayKey(String key) {
        return key.startsWith(PACKET_PREFIX) || key.startsWith(NONCE_PREFIX);
    }

    /**
     * Normalizes the supplied identifier into the comparison/storage form used by the accepted-packet
     * replay history.
     *
     * @param player the player supplied to this operation
     * @return the result described above
     */
    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT);
    }
}
