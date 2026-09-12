package dev.krypt04mcg.protocol;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class OptionalTransferAssemblerTest {
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
}
