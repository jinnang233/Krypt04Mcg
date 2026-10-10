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

    /**
     * Creates a transfer progress tracker with the supplied dependencies and initial state.
     */
    public TransferProgressTracker() {
        this(System::nanoTime);
    }

    /**
     * Creates a transfer progress tracker with the supplied dependencies and initial state.
     *
     * @param clock the time source used for deadline or expiry checks
     */
    public TransferProgressTracker(LongSupplier clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    /**
     * Performs the accept operation for the bounded transfer progress state.
     *
     * @param update the update supplied to this operation
     */
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

    /**
     * Performs the snapshot operation for the bounded transfer progress state.
     *
     * @param direction the direction supplied to this operation
     * @return the result described above
     */
    public List<Update> snapshot(Direction direction) {
        cleanup();
        return entries.values().stream().map(TimedUpdate::update)
                .filter(update -> update.direction() == direction)
                .sorted(Comparator.comparing(update -> update.status().terminal()))
                .toList();
    }

    /**
     * Clears retained state in the bounded transfer progress state.
     */
    public void clear() {
        entries.clear();
    }

    /**
     * Performs the count operation for the bounded transfer progress state.
     *
     * @param direction the direction supplied to this operation
     * @return the result described above
     */
    private long count(Direction direction) {
        return entries.keySet().stream().filter(key -> key.direction() == direction).count();
    }

    /**
     * Removes expired or retired state in the bounded transfer progress state.
     */
    private void cleanup() {
        long now = clock.getAsLong();
        entries.values().removeIf(entry -> entry.update().status().terminal()
                && now - entry.updatedAt() >= RESULT_VISIBLE_NANOS);
    }

    public enum Direction { SEND, RECEIVE }

    public enum Status {
        QUEUED, TRANSFERRING, VERIFYING, COMPLETE, FAILED, TIMED_OUT, CANCELLED;

        /**
         * Performs the terminal operation for the bounded transfer progress state.
         *
         * @return whether the condition or operation described above succeeds
         */
        public boolean terminal() {
            return this == COMPLETE || this == FAILED || this == TIMED_OUT || this == CANCELLED;
        }
    }

    public record Update(Direction direction, String id, String peer, int completed, int total, Status status) {
        /**
         * Creates a update with the supplied dependencies and initial state.
         *
         * @param direction the direction supplied to this operation
         * @param id the id supplied to this operation
         * @param peer the peer identifier associated with this operation
         * @param completed the completed supplied to this operation
         * @param total the total supplied to this operation
         * @param status the status supplied to this operation
         */
        public Update {
            Objects.requireNonNull(direction);
            Objects.requireNonNull(id);
            Objects.requireNonNull(peer);
            Objects.requireNonNull(status);
            if (total <= 0 || completed < 0 || completed > total) {
                throw new IllegalArgumentException("Invalid transfer counts");
            }
        }

        /**
         * Performs the percent operation for the bounded transfer progress state.
         *
         * @return the result described above
         */
        public int percent() {
            return (int) (100L * completed / total);
        }
    }

    private record Key(Direction direction, String id) {}
    private record TimedUpdate(Update update, long updatedAt) {}
}
