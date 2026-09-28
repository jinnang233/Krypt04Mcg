package dev.krypt04mcg.service;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TunnelCountersTest {
    @TempDir Path root;
    private static final String EPOCH = "AAAAAAAAAAAAAAAAAAAAAA";
    @Test void restartSkipsReservedStreamAndRejectsOldOpen() throws Exception {
        var first = new TunnelCounters(root);
        assertEquals(0, first.reserve("Bob", EPOCH));
        // Simulate a crash after reservation, before sending OPEN.
        var restart = new TunnelCounters(root);
        assertEquals(1, restart.reserve("Bob", EPOCH));
        restart.accept("Bob", EPOCH, 1);
        assertThrows(IOException.class, () -> new TunnelCounters(root).accept("Bob", EPOCH, 1));
        assertThrows(IOException.class, () -> new TunnelCounters(root).accept("Bob", EPOCH, 0));
        new TunnelCounters(root).accept("Bob", EPOCH, 2);
    }
    @Test void multipleInstancesCannotReserveTheSameLease() throws Exception {
        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            Set<Long> leases = new HashSet<>();
            List<Future<Long>> results = new ArrayList<>();
            for (int i = 0; i < 16; i++)
                results.add(workers.submit(() -> new TunnelCounters(root).reserve("Bob", EPOCH)));
            for (var result : results) assertTrue(leases.add(result.get(10, TimeUnit.SECONDS)));
            assertEquals(16, new TunnelCounters(root).reserve("Bob", EPOCH));
        }
    }
}
