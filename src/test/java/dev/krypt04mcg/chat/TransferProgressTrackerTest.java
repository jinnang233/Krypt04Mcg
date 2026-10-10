package dev.krypt04mcg.chat;

import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicLong;
import static dev.krypt04mcg.chat.TransferProgressTracker.*;
import static org.junit.jupiter.api.Assertions.*;

class TransferProgressTrackerTest {
    private final AtomicLong now = new AtomicLong();
    private final TransferProgressTracker tracker = new TransferProgressTracker(now::get);

    /**
     * Provides the add fixture operation used by the transfer progress tracker test regression scenarios.
     *
     * @param direction the direction supplied to this operation
     * @param id the id supplied to this operation
     * @param completed the completed supplied to this operation
     * @param status the status supplied to this operation
     */
    private void add(Direction direction, String id, int completed, Status status) {
        tracker.accept(new Update(direction, id, "Alice", completed, 3, status));
    }

    /**
     * Verifies that updates in place with exact counts and independent directions.
     */
    @Test void updatesInPlaceWithExactCountsAndIndependentDirections() {
        add(Direction.SEND, "same-id", 1, Status.TRANSFERRING);
        add(Direction.RECEIVE, "same-id", 2, Status.TRANSFERRING);
        add(Direction.SEND, "same-id", 2, Status.TRANSFERRING);
        assertEquals(1, tracker.snapshot(Direction.SEND).size());
        assertEquals(66, tracker.snapshot(Direction.SEND).getFirst().percent());
        assertEquals(2, tracker.snapshot(Direction.RECEIVE).getFirst().completed());
    }

    /**
     * Verifies that receive flood cannot displace active entries or send progress.
     */
    @Test void receiveFloodCannotDisplaceActiveEntriesOrSendProgress() {
        add(Direction.SEND, "sending", 0, Status.QUEUED);
        for (int i = 0; i < 10_000; i++) add(Direction.RECEIVE, "rx" + i, 1, Status.TRANSFERRING);
        var rows = tracker.snapshot(Direction.RECEIVE);
        assertEquals(MAX_ENTRIES_PER_DIRECTION, rows.size());
        assertEquals("rx0", rows.getFirst().id());
        assertEquals("sending", tracker.snapshot(Direction.SEND).getFirst().id());
    }

    /**
     * Verifies that active transfers survive three seconds and results expire without traffic.
     */
    @Test void activeTransfersSurviveThreeSecondsAndResultsExpireWithoutTraffic() {
        add(Direction.SEND, "waiting", 0, Status.QUEUED);
        add(Direction.RECEIVE, "done", 3, Status.COMPLETE);
        now.set(RESULT_VISIBLE_NANOS - 1);
        assertEquals(1, tracker.snapshot(Direction.RECEIVE).size());
        now.incrementAndGet();
        assertTrue(tracker.snapshot(Direction.RECEIVE).isEmpty());
        assertEquals(1, tracker.snapshot(Direction.SEND).size());
    }

    /**
     * Verifies that repeated terminal events do not renew the result lifetime.
     */
    @Test void repeatedTerminalEventsDoNotRenewTheResultLifetime() {
        add(Direction.SEND, "done", 3, Status.COMPLETE);
        now.set(RESULT_VISIBLE_NANOS - 1);
        add(Direction.SEND, "done", 3, Status.COMPLETE);
        now.incrementAndGet();
        assertTrue(tracker.snapshot(Direction.SEND).isEmpty());
    }

    /**
     * Verifies that reclaims terminal capacity and prioritizes pending transfers.
     */
    @Test void reclaimsTerminalCapacityAndPrioritizesPendingTransfers() {
        for (int i = 0; i < MAX_ENTRIES_PER_DIRECTION; i++) add(Direction.RECEIVE, "done" + i, 3, Status.COMPLETE);
        add(Direction.RECEIVE, "active", 1, Status.TRANSFERRING);
        var rows = tracker.snapshot(Direction.RECEIVE);
        assertEquals(MAX_ENTRIES_PER_DIRECTION, rows.size());
        assertEquals("active", rows.getFirst().id());
        assertTrue(rows.stream().noneMatch(row -> row.id().equals("done0")));
    }

    /**
     * Verifies that clear removes all connection state.
     */
    @Test void clearRemovesAllConnectionState() {
        add(Direction.SEND, "tx", 1, Status.TRANSFERRING);
        add(Direction.RECEIVE, "rx", 2, Status.TRANSFERRING);
        tracker.clear();
        assertTrue(tracker.snapshot(Direction.SEND).isEmpty());
        assertTrue(tracker.snapshot(Direction.RECEIVE).isEmpty());
    }
}
