package dev.krypt04mcg.chat;

import java.time.Duration;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** Client-thread HUD state; contains counts and peer labels, never message content. */
public final class TransferProgressTracker implements Consumer<TransferProgressTracker.Update> {
    public static final int MAX_ENTRIES_PER_DIRECTION = 32;
    public static final long RESULT_VISIBLE_NANOS = Duration.ofSeconds(3).toNanos();
    private final Map<Key, TimedUpdate> entries = new LinkedHashMap<>();
    private final LongSupplier clock;

    public TransferProgressTracker() {
        this(System::nanoTime);
    }

    public TransferProgressTracker(LongSupplier clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public void accept(Update update) {
        cleanup();
        Key key = new Key(update.direction(), update.id());
        TimedUpdate previous = entries.get(key);
        if (previous != null && previous.update().equals(update)) return;
        if (previous == null && count(update.direction()) >= MAX_ENTRIES_PER_DIRECTION) {
            // A flood of new IDs must not displace a transfer already on screen.
            Key finished = entries.entrySet().stream()
                    .filter(e -> e.getKey().direction() == update.direction() && e.getValue().update().status().terminal())
                    .map(Map.Entry::getKey).findFirst().orElse(null);
            if (finished == null) return;
            entries.remove(finished);
        }
        entries.put(key, new TimedUpdate(update, clock.getAsLong()));
    }

    public List<Update> snapshot(Direction direction) {
        cleanup();
        return entries.values().stream().map(TimedUpdate::update)
                .filter(update -> update.direction() == direction)
                .sorted(Comparator.comparing(update -> update.status().terminal()))
                .toList();
    }

    public void clear() {
        entries.clear();
    }

    private long count(Direction direction) {
        return entries.keySet().stream().filter(key -> key.direction() == direction).count();
    }

    private void cleanup() {
        long now = clock.getAsLong();
        entries.values().removeIf(entry -> entry.update().status().terminal()
                && now - entry.updatedAt() >= RESULT_VISIBLE_NANOS);
    }

    public enum Direction { SEND, RECEIVE }

    public enum Status {
        QUEUED, TRANSFERRING, VERIFYING, COMPLETE, FAILED, TIMED_OUT, CANCELLED;

        public boolean terminal() {
            return this == COMPLETE || this == FAILED || this == TIMED_OUT || this == CANCELLED;
        }
    }

    public record Update(Direction direction, String id, String peer, int completed, int total, Status status) {
        public Update {
            Objects.requireNonNull(direction);
            Objects.requireNonNull(id);
            Objects.requireNonNull(peer);
            Objects.requireNonNull(status);
            if (total <= 0 || completed < 0 || completed > total) {
                throw new IllegalArgumentException("Invalid transfer counts");
            }
        }

        public int percent() {
            return (int) (100L * completed / total);
        }
    }

    private record Key(Direction direction, String id) {}
    private record TimedUpdate(Update update, long updatedAt) {}
}
