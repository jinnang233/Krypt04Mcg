package dev.krypt04mcg.protocol;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class OptionalTransferAssemblerTest {
    @Test void deniedAdmissionDoesNotReserveTheOnlyFileSlot() {
        var assembler = new OptionalTransferAssembler(2048, 1);
        String fragment = UUID.randomUUID() + ":0:2048:x";
        assertTrue(assembler.accept("Mallory", fragment, 0, () -> false).isEmpty());
        assertEquals("ok", assembler.accept("Alice", OptionalTransferAssembler.split("ok").getFirst(), 1).orElseThrow());
        assertTrue(assembler.accept("Mallory", fragment, 2, () -> true).isEmpty());
    }

    @Test void oneSenderCannotReserveEverySlotAndDuplicatesDoNotCompleteTransfer() {
        var assembler = new OptionalTransferAssembler(128, 2);
        String id = UUID.randomUUID().toString();
        assertTrue(assembler.accept("Alice", id + ":0:2:x", 0).isEmpty());
        for (int i = 0; i < 100; i++) {
            assertTrue(assembler.accept("ALICE", id + ":0:2:x", i).isEmpty());
            assertTrue(assembler.accept("ALICE", UUID.randomUUID() + ":0:2:x", i).isEmpty());
        }
        assertEquals("ok", assembler.accept("Bob", OptionalTransferAssembler.split("ok").getFirst(), 100).orElseThrow());
        assertEquals("xy", assembler.accept("Alice", id + ":1:2:y", 101,
                () -> { fail("Admission must run only once"); return false; }).orElseThrow());
    }

    @Test void conflictsRetireTransferAndImmediatelyReleaseStorage() {
        var assembler = new OptionalTransferAssembler(128, 1);
        for (String conflicting : List.of(":0:2:y", ":1:3:y")) {
            String id = UUID.randomUUID().toString();
            assembler.accept("Alice", id + ":0:2:x", 0);
            assertThrows(IllegalArgumentException.class, () -> assembler.accept("Alice", id + conflicting, 1));
            assertTrue(assembler.accept("Alice", id + ":1:2:y", 2).isEmpty());
            assertEquals("ok", assembler.accept("Bob", OptionalTransferAssembler.split("ok").getFirst(), 3).orElseThrow());
        }
    }

    @Test void rejectsMalformedHeadersAndEmptyChunksBeforeAdmission() {
        var assembler = new OptionalTransferAssembler();
        String id = UUID.randomUUID().toString();
        for (String fragment : List.of("1-1-1-1-1:0:1:x", id + ":+0:1:x", id + ":0:1:",
                id + ":0:1:" + "x".repeat(OptionalTransferAssembler.CHUNK + 1), "x".repeat(20000))) {
            assertThrows(IllegalArgumentException.class, () -> assembler.accept("Alice", fragment, 0,
                    () -> { fail("Invalid chunks must not reach admission"); return true; }));
        }
        assertThrows(IllegalArgumentException.class, () -> assembler.accept("x".repeat(1000), id + ":0:1:x", 0));
    }

    @Test void completedTransferCannotBeReplayedUnderDifferentSenderCase() {
        var assembler = new OptionalTransferAssembler();
        String fragment = OptionalTransferAssembler.split("public-key").getFirst();
        assertEquals("public-key", assembler.accept("Alice", fragment, 0).orElseThrow());
        assertTrue(assembler.accept("ALICE", fragment, 1).isEmpty());
    }

    @Test void idleExpiryReleasesIncompleteFileSlotAndRejectsItsLateChunks() {
        var assembler = new OptionalTransferAssembler(2048, 1);
        var parts = OptionalTransferAssembler.split("x".repeat(24000));
        assertTrue(assembler.accept("Alice", parts.getFirst(), 0).isEmpty());
        assembler.expire(60001);
        assertTrue(assembler.accept("Alice", parts.getLast(), 60002).isEmpty());
        assertEquals("new", assembler.accept("Bob", OptionalTransferAssembler.split("new").getFirst(), 60003).orElseThrow());
    }
    @Test void assemblesLargeKeysOutOfOrderAndIsolatesSenders() {
        String data = "x".repeat(400000);
        List<String> parts = new ArrayList<>(OptionalTransferAssembler.split(data));
        Collections.reverse(parts);
        var assembler = new OptionalTransferAssembler();
        Optional<String> result = Optional.empty();
        for (String part : parts) result = assembler.accept("Alice", part, 1000);
        assertEquals(data, result.orElseThrow());
        assertTrue(assembler.accept("Bob", parts.getFirst(), 1000).isEmpty());
    }

    @Test void rejectsUnboundedAndConflictingTransfers() {
        var assembler = new OptionalTransferAssembler();
        String id = UUID.randomUUID().toString();
        assertThrows(IllegalArgumentException.class, () -> assembler.accept("Alice", id + ":0:129:x", 0));
        assertThrows(IllegalArgumentException.class, () -> assembler.accept("Alice", id + ":-1:1:x", 0));
        assembler.accept("Alice", id + ":0:2:x", 0);
        assertThrows(IllegalArgumentException.class, () -> assembler.accept("Alice", id + ":0:2:y", 1));
        assertTrue(assembler.accept("Alice", id + ":1:2:y", 60001).isEmpty());
        assembler.clear();
        assertTrue(assembler.accept("Alice", id + ":0:2:x", 60002).isEmpty());
    }

    @Test void assemblesLargestCmceSizedPublicIdentity() {
        String data = "x".repeat(1_850_000);
        List<String> parts = OptionalTransferAssembler.split(data, OptionalTransferAssembler.MAX_KEY_CHUNKS);
        assertTrue(parts.size() > OptionalTransferAssembler.MAX_CHUNKS);
        var assembler = new OptionalTransferAssembler(OptionalTransferAssembler.MAX_KEY_CHUNKS, 4);
        Optional<String> result = Optional.empty();
        for (String part : parts) result = assembler.accept("Alice", part, 1000);
        assertEquals(data, result.orElseThrow());
    }
}
