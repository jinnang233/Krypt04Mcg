package dev.krypt04mcg.chat;

import dev.krypt04mcg.model.ChatSendFragment;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.config.ChatSendMode;

import java.util.ArrayDeque;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/** Bounded, connection-bound queue, accessed only on the client thread. */
final class FragmentSendQueue {
    static final int MAX_PENDING_FRAGMENTS = 2048;
    private final ArrayDeque<Delivery> pending = new ArrayDeque<>();
    private final Supplier<?> connection;
    private final LongSupplier clock;
    private long nextSend;
    private long nextBatchId;
    private Consumer<TransferProgressTracker.Update> progress = ignored -> {};

    FragmentSendQueue(Supplier<?> connection, LongSupplier clock) {
        this.connection = connection;
        this.clock = clock;
        this.nextSend = clock.getAsLong();
    }

    void enqueue(String receiver, List<String> fragments, Consumer<ChatSendFragment> sender) {
        enqueue(receiver, fragments, sender, -1, Long.MAX_VALUE);
    }

    void enqueue(String receiver, List<String> fragments, Consumer<ChatSendFragment> sender,
                 int delayMillis, long queueBudgetMillis) {
        Object current = connection.get();
        discardStale(current);
        if (current == null) throw new IllegalStateException("Not connected to a server");
        if (fragments.size() > MAX_PENDING_FRAGMENTS - pending.size()) {
            throw new IllegalStateException("Encrypted message send queue is full");
        }
        if (fragments.isEmpty()) return;
        Objects.requireNonNull(sender);
        long now = clock.getAsLong();
        if (delayMillis >= 0) {
            long duration = Math.max(0, nextSend - now);
            for (Delivery delivery : pending) duration += Math.max(50, delivery.batch.delayMillis) * 1_000_000L;
            duration += (long) (fragments.size() - 1) * Math.max(50, delayMillis) * 1_000_000L;
            if (duration >= queueBudgetMillis * 1_000_000L) {
                throw new IllegalStateException("Encrypted chat queue would exceed its deadline; wait for the current transfer");
            }
        }
        Batch batch = new Batch(Long.toUnsignedString(++nextBatchId), receiver, fragments.size(),
                delayMillis, now, queueBudgetMillis);
        for (String fragment : fragments) {
            pending.addLast(new Delivery(current, sender,
                    new ChatSendFragment(receiver, fragment, EncryptedPacket.VERSION), batch));
        }
        report(batch, TransferProgressTracker.Status.QUEUED);
    }

    void setProgressListener(Consumer<TransferProgressTracker.Update> progress) {
        this.progress = Objects.requireNonNull(progress);
    }

    boolean tick(ChatSendMode mode, int delayMillis) {
        // Vanilla chat and commands add 20 spam ticks per message, draining one per tick.
        return tick(mode == ChatSendMode.CUSTOM_PAYLOAD ? delayMillis : Math.max(1000, delayMillis));
    }

    boolean tick(int delayMillis) {
        discardStale(connection.get());
        long now = clock.getAsLong();
        if (pending.isEmpty() || now - nextSend < 0) return false;
        Delivery delivery = pending.removeFirst();
        nextSend = now + Math.max(0, delivery.batch.delayMillis >= 0
                ? delivery.batch.delayMillis : delayMillis) * 1_000_000L;
        try {
            if (delivery.batch.delayMillis >= 0
                    && now - delivery.batch.queuedAt >= delivery.batch.queueBudgetMillis * 1_000_000L) {
                throw new IllegalStateException("Encrypted chat send deadline expired; send a new message");
            }
            delivery.sender.accept(delivery.fragment);
        } catch (RuntimeException e) {
            report(delivery.batch, TransferProgressTracker.Status.FAILED);
            cancelPending(delivery.batch);
            throw e;
        }
        delivery.batch.sent++;
        report(delivery.batch, delivery.batch.sent == delivery.batch.total
                ? TransferProgressTracker.Status.COMPLETE : TransferProgressTracker.Status.TRANSFERRING);
        return true;
    }

    void clear() {
        cancelPending(null);
    }

    private void cancelPending(Batch failed) {
        var cancelled = new LinkedHashSet<Batch>();
        for (Delivery delivery : pending) {
            if (delivery.batch != failed && cancelled.add(delivery.batch)) {
                report(delivery.batch, TransferProgressTracker.Status.CANCELLED);
            }
        }
        pending.clear();
        nextSend = clock.getAsLong();
    }

    private void discardStale(Object current) {
        if (!pending.isEmpty() && pending.peekFirst().connection != current) clear();
    }

    private void report(Batch batch, TransferProgressTracker.Status status) {
        progress.accept(new TransferProgressTracker.Update(TransferProgressTracker.Direction.SEND,
                batch.id, batch.receiver, batch.sent, batch.total, status));
    }

    private static final class Batch {
        private final String id;
        private final String receiver;
        private final int total;
        private final int delayMillis;
        private final long queuedAt;
        private final long queueBudgetMillis;
        private int sent;

        private Batch(String id, String receiver, int total, int delayMillis, long queuedAt, long queueBudgetMillis) {
            this.id = id;
            this.receiver = receiver;
            this.total = total;
            this.delayMillis = delayMillis;
            this.queuedAt = queuedAt;
            this.queueBudgetMillis = queueBudgetMillis;
        }
    }

    private record Delivery(Object connection, Consumer<ChatSendFragment> sender, ChatSendFragment fragment, Batch batch) {}
}
