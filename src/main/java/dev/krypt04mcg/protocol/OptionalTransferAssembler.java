package dev.krypt04mcg.protocol;

import java.util.*;

/** Bounded, expiring assembly shared by the two optional channels. */
public final class OptionalTransferAssembler {
    public static final int CHUNK = 12000;
    public static final int MAX_CHUNKS = 128;
    private final Map<String, Entry> entries = new HashMap<>();
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
        entries.values().removeIf(e -> now - e.created > 60000);
        String[] parts = fragment.split(":", 4);
        if (parts.length != 4 || parts[3].length() > CHUNK) throw new IllegalArgumentException("Invalid chunk");
        String id = UUID.fromString(parts[0]).toString();
        int index = Integer.parseInt(parts[1]), total = Integer.parseInt(parts[2]);
        if (total < 1 || total > maxChunks || index < 0 || index >= total) throw new IllegalArgumentException("Invalid chunk index");
        String key = sender.toLowerCase(Locale.ROOT) + ":" + id;
        Entry entry = entries.get(key);
        if (entry == null) {
            if (entries.size() >= maxTransfers) throw new IllegalArgumentException("Too many transfers");
            entry = new Entry(now, new String[total]);
            entries.put(key, entry);
        }
        if (entry.parts.length != total) throw new IllegalArgumentException("Chunk count changed");
        if (entry.parts[index] != null && !entry.parts[index].equals(parts[3])) throw new IllegalArgumentException("Conflicting chunk");
        entry.parts[index] = parts[3];
        if (Arrays.stream(entry.parts).anyMatch(Objects::isNull)) return Optional.empty();
        entries.remove(key);
        return Optional.of(String.join("", entry.parts));
    }

    public void clear() { entries.clear(); }
    private record Entry(long created, String[] parts) {}
}
