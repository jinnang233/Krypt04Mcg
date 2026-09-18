package dev.krypt04mcg.chat;

import dev.krypt04mcg.model.ChatSendFragment;
import dev.krypt04mcg.model.EncryptedPacket;

import java.util.ArrayDeque;
import java.util.List;
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

    FragmentSendQueue(Supplier<?> connection, LongSupplier clock) {
        this.connection = connection;
        this.clock = clock;
    }

    void enqueue(String receiver, List<String> fragments, Consumer<ChatSendFragment> sender) {
        Object current = connection.get();
        discardStale(current);
        if (current == null) throw new IllegalStateException("Not connected to a server");
        if (fragments.size() > MAX_PENDING_FRAGMENTS - pending.size()) {
            throw new IllegalStateException("Encrypted message send queue is full");
        }
        for (String fragment : fragments) {
            pending.addLast(new Delivery(current, sender,
                    new ChatSendFragment(receiver, fragment, EncryptedPacket.VERSION)));
        }
    }

    boolean tick(int delayMillis) {
        discardStale(connection.get());
        long now = clock.getAsLong();
        if (pending.isEmpty() || now - nextSend < 0) return false;
        Delivery delivery = pending.removeFirst();
        nextSend = now + Math.max(0, delayMillis) * 1_000_000L;
        try {
            delivery.sender.accept(delivery.fragment);
        } catch (RuntimeException e) {
            clear();
            throw e;
        }
        return true;
    }

    void clear() {
        pending.clear();
        nextSend = clock.getAsLong();
    }

    private void discardStale(Object current) {
        if (!pending.isEmpty() && pending.peekFirst().connection != current) clear();
        if (pending.isEmpty()) nextSend = clock.getAsLong();
    }

    private record Delivery(Object connection, Consumer<ChatSendFragment> sender, ChatSendFragment fragment) {}
}
