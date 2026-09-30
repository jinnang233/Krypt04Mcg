package dev.krypt04mcg.chat;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

final class FragmentSendQueueTest {
    private final AtomicReference<Object> connection = new AtomicReference<>(new Object());
    private final AtomicLong now = new AtomicLong();
    private final FragmentSendQueue queue = new FragmentSendQueue(connection::get, now::get);
    private final List<String> sent = new ArrayList<>();

    private void enqueue(String... fragments) {
        queue.enqueue("bob", List.of(fragments), value -> sent.add(value.fragment()));
    }

    @Test void switchingServersDiscardsRemainingFragments() {
        enqueue("first", "secret-old-server");
        assertTrue(queue.tick(250));
        connection.set(new Object());
        now.set(1_000_000_000L);
        assertFalse(queue.tick(250));
        enqueue("new-server");
        assertTrue(queue.tick(250));
        assertEquals(List.of("first", "new-server"), sent);
    }

    @Test void disconnectRejectsNewWorkAndDropsPendingWork() {
        enqueue("old");
        connection.set(null);
        assertThrows(IllegalStateException.class, () -> enqueue("offline"));
        connection.set(new Object());
        assertFalse(queue.tick(0));
        assertTrue(sent.isEmpty());
    }

    @Test void queueIsBoundedAndAdmissionIsAtomic() {
        queue.enqueue("bob", Collections.nCopies(FragmentSendQueue.MAX_PENDING_FRAGMENTS - 1, "part"),
                value -> sent.add(value.fragment()));
        assertThrows(IllegalStateException.class, () -> enqueue("overflow1", "overflow2"));
        enqueue("last");
        for (int i = 0; i < FragmentSendQueue.MAX_PENDING_FRAGMENTS; i++) assertTrue(queue.tick(0));
        assertFalse(queue.tick(0));
        assertEquals("last", sent.getLast());
        assertFalse(sent.contains("overflow1"));
    }

    @Test void sendsInOrderOnCallingThreadAndRespectsDelay() {
        Thread clientThread = Thread.currentThread();
        queue.enqueue("bob", List.of("one", "two"), value -> {
            assertSame(clientThread, Thread.currentThread());
            sent.add(value.fragment());
        });
        assertTrue(queue.tick(250));
        now.set(249_000_000L);
        assertFalse(queue.tick(250));
        now.set(250_000_000L);
        assertTrue(queue.tick(250));
        assertEquals(List.of("one", "two"), sent);
    }

    @Test void clearingOrTransportFailureCancelsRemainingWork() {
        enqueue("cancelled");
        queue.clear();
        assertFalse(queue.tick(0));
        queue.enqueue("bob", List.of("failure", "must-not-send"), value -> {
            throw new IllegalStateException("channel unavailable");
        });
        assertThrows(IllegalStateException.class, () -> queue.tick(0));
        assertFalse(queue.tick(0));
        enqueue("recovered");
        assertTrue(queue.tick(0));
        assertEquals(List.of("recovered"), sent);
    }
}
