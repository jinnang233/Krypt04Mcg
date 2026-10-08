package dev.krypt04mcg.chat;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

final class FragmentSendQueueTest {
    @Test void maximumBatchCompletesBeforeAssemblyDeadlineAtCapturedPayloadPacing() {
        queue.enqueue("bob", Collections.nCopies(2048, "part"), value -> sent.add(value.fragment()), 50, 110_000);
        for (int i = 0; i < 2048; i++) {
            now.set(i * 50_000_000L);
            assertTrue(queue.tick(dev.krypt04mcg.config.ChatSendMode.CHAT, 1000));
        }
        assertEquals(2048, sent.size());
        assertTrue(now.get() < 120_000_000_000L);
    }

    @Test void admissionRejectsQueueThatWouldMissDeadlineWithoutDiscardingExistingWork() {
        queue.enqueue("bob", Collections.nCopies(100, "part"), value -> sent.add(value.fragment()), 1000, 110_000);
        assertThrows(IllegalStateException.class,
                () -> queue.enqueue("alice", List.of("overflow"), value -> sent.add(value.fragment()), 50, 30_000));
        for (int i = 0; i < 100; i++) {
            now.set(i * 1_000_000_000L);
            assertTrue(queue.tick(0));
        }
        assertEquals(100, sent.size());
        assertFalse(sent.contains("overflow"));
    }

    @Test void stalledClientCancelsExpiredCiphertextBeforeSubmission() {
        queue.enqueue("bob", List.of("one", "two"), value -> sent.add(value.fragment()), 50, 110_000);
        assertTrue(queue.tick(0));
        now.set(110_000_000_000L);
        assertThrows(IllegalStateException.class, () -> queue.tick(0));
        assertEquals(List.of("one"), sent);
        assertFalse(queue.tick(0));
    }
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

    @Test void vanillaPacingSurvivesEmptyQueueBetweenMessages() {
        for (var mode : List.of(dev.krypt04mcg.config.ChatSendMode.CHAT,
                dev.krypt04mcg.config.ChatSendMode.SERVER_COMMAND)) {
            queue.clear();
            enqueue("one");
            assertTrue(queue.tick(mode, 250));
            enqueue("two");
            now.addAndGet(250_000_000L);
            assertFalse(queue.tick(mode, 250));
            now.addAndGet(750_000_000L);
            assertTrue(queue.tick(mode, 250));
        }
    }

    @Test void customPayloadRetainsConfiguredPacing() {
        enqueue("one", "two");
        assertTrue(queue.tick(dev.krypt04mcg.config.ChatSendMode.CUSTOM_PAYLOAD, 250));
        now.set(250_000_000L);
        assertTrue(queue.tick(dev.krypt04mcg.config.ChatSendMode.CUSTOM_PAYLOAD, 250));
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

    @Test void progressCountsOnlySuccessfulSubmissionsPerQueuedMessage() {
        var updates = new ArrayList<TransferProgressTracker.Update>();
        queue.setProgressListener(updates::add);
        enqueue("one", "two");
        queue.enqueue("alice", List.of("other"), value -> sent.add(value.fragment()));
        assertEquals(0, updates.getFirst().completed());
        assertEquals(TransferProgressTracker.Status.QUEUED, updates.getFirst().status());
        assertTrue(queue.tick(250));
        var first = updates.getLast();
        assertEquals(1, first.completed());
        assertEquals(50, first.percent());
        assertEquals(TransferProgressTracker.Status.TRANSFERRING, first.status());
        assertFalse(queue.tick(250));
        assertEquals(first, updates.getLast());
        now.set(250_000_000L);
        assertTrue(queue.tick(250));
        assertEquals(100, updates.getLast().percent());
        assertEquals(TransferProgressTracker.Status.COMPLETE, updates.getLast().status());
        now.set(500_000_000L);
        assertTrue(queue.tick(250));
        assertNotEquals(first.id(), updates.getLast().id());
        assertEquals("alice", updates.getLast().peer());
    }

    @Test void transportFailureDoesNotCountFailedSubmissionAndCancelsOtherBatchesOnce() {
        var updates = new ArrayList<TransferProgressTracker.Update>();
        queue.setProgressListener(updates::add);
        queue.enqueue("bob", List.of("one", "fails", "must-not-send"), value -> {
            if (value.fragment().equals("fails")) throw new IllegalStateException("channel unavailable");
            sent.add(value.fragment());
        });
        enqueue("other", "cancelled");
        assertTrue(queue.tick(0));
        assertThrows(IllegalStateException.class, () -> queue.tick(0));
        var failure = updates.stream().filter(p -> p.status() == TransferProgressTracker.Status.FAILED).toList();
        assertEquals(1, failure.size());
        assertEquals(1, failure.getFirst().completed());
        assertEquals(1, updates.stream().filter(p -> p.status() == TransferProgressTracker.Status.CANCELLED).count());
        assertFalse(queue.tick(0));
        assertEquals(List.of("one"), sent);
    }

    @Test void switchingConnectionsCancelsProgressForEveryPendingBatch() {
        var updates = new ArrayList<TransferProgressTracker.Update>();
        queue.setProgressListener(updates::add);
        enqueue("one", "two");
        enqueue("other");
        assertTrue(queue.tick(0));
        connection.set(new Object());
        assertFalse(queue.tick(0));
        assertEquals(2, updates.stream().filter(p -> p.status() == TransferProgressTracker.Status.CANCELLED).count());
        assertEquals(List.of("one"), sent);
    }
}
