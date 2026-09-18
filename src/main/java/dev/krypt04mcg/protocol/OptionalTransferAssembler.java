package dev.krypt04mcg.protocol;

import java.util.*;
import java.util.function.BooleanSupplier;

/** Bounded, expiring assembly shared by the two optional channels. */
public final class OptionalTransferAssembler {
    public static final int CHUNK = 12000;
    public static final int MAX_CHUNKS = 128;
    public static final int MAX_KEY_CHUNKS = 256;
    private final Map<String, Entry> entries = new HashMap<>();
    private final Map<String, Long> retired = new HashMap<>();
    private final int maxChunks;
    private final int maxTransfers;

    public OptionalTransferAssembler() { this(MAX_CHUNKS, 4); }
    public OptionalTransferAssembler(int maxChunks, int maxTransfers) {
        if (maxChunks < 1 || maxChunks > 2048 || maxTransfers < 1 || maxTransfers > 4)
            throw new IllegalArgumentException("Invalid transfer limits");
        this.maxChunks = maxChunks;
        this.maxTransfers = maxTransfers;
    }

    public static List<String> split(String data) {
        return split(data, MAX_CHUNKS);
    }

    public static List<String> split(String data, int maxChunks) {
        if (maxChunks < 1 || maxChunks > 2048) throw new IllegalArgumentException("Invalid chunk limit");
        int total = (data.length() + CHUNK - 1) / CHUNK;
        if (total < 1 || total > maxChunks) throw new IllegalArgumentException("Transfer too large");
        String id = UUID.randomUUID().toString();
        List<String> result = new ArrayList<>();
        for (int i = 0; i < total; i++) result.add(id + ":" + i + ":" + total + ":"
                + data.substring(i * CHUNK, Math.min(data.length(), (i + 1) * CHUNK)));
        return result;
    }

    public Optional<String> accept(String sender, String fragment, long now) {
        return accept(sender, fragment, now, () -> true);
    }

    /** Admission is checked before reserving storage, only for a new transfer. */
    public Optional<String> accept(String sender, String fragment, long now, BooleanSupplier admission) {
        expire(now);
        if (sender == null || !sender.matches("[A-Za-z0-9_]{1,16}") || fragment == null
                || fragment.length() > CHUNK + 47) throw new IllegalArgumentException("Invalid chunk");
        String[] parts = fragment.split(":", 4);
        if (parts.length != 4 || parts[3].isEmpty() || parts[3].length() > CHUNK
                || parts[0].length() != 36 || !parts[1].matches("[0-9]{1,4}")
                || !parts[2].matches("[0-9]{1,4}")) throw new IllegalArgumentException("Invalid chunk");
        String id = UUID.fromString(parts[0]).toString();
        if (!id.equalsIgnoreCase(parts[0])) throw new IllegalArgumentException("Invalid transfer id");
        int index = Integer.parseInt(parts[1]), total = Integer.parseInt(parts[2]);
        if (total < 1 || total > maxChunks || index < 0 || index >= total) throw new IllegalArgumentException("Invalid chunk index");
        String key = sender.toLowerCase(Locale.ROOT) + ":" + id;
        if (retired.containsKey(key)) return Optional.empty();
        Entry entry = entries.get(key);
        if (entry == null) {
            if (retired.size() + entries.size() >= 1024) return Optional.empty();
            if (entries.size() >= maxTransfers) return Optional.empty();
            // One sender must not reserve every public-key assembly slot.
            String prefix = sender.toLowerCase(Locale.ROOT) + ":";
            if (entries.keySet().stream().anyMatch(k -> k.startsWith(prefix)) || !admission.getAsBoolean())
                return Optional.empty();
            entry = new Entry(now, new String[total]);
            entries.put(key, entry);
        }
        if (entry.parts.length != total || (entry.parts[index] != null && !entry.parts[index].equals(parts[3]))) {
            entries.remove(key);
            retired.put(key, now);
            throw new IllegalArgumentException("Conflicting chunk");
        }
        if (entry.parts[index] != null) return Optional.empty();
        entry.parts[index] = parts[3];
        if (++entry.received != total) return Optional.empty();
        entries.remove(key);
        retired.put(key, now);
        return Optional.of(String.join("", entry.parts));
    }

    /** Called by the client tick as well as receive, so idle connections release payloads. */
    public void expire(long now) {
        retired.values().removeIf(time -> now - time > 60000);
        var iterator = entries.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (now - entry.getValue().created > 60000) {
                retired.put(entry.getKey(), now);
                iterator.remove();
            }
        }
    }

    public void clear() { entries.clear(); retired.clear(); }
    private static final class Entry {
        final long created;
        final String[] parts;
        int received;

        Entry(long created, String[] parts) { this.created = created; this.parts = parts; }
    }
}
