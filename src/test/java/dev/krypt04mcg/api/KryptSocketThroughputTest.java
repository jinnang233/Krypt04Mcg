package dev.krypt04mcg.api;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class KryptSocketThroughputTest {
    @Test @Timeout(20)
    void streamsMoreThanTheQueueCapacityAndClosesAfterLastData() throws Exception {
        UUID id = UUID.randomUUID();
        var target = new KryptSocket("Alice", "test", id, frame -> fail("Receiver must not ACK"));
        var source = new KryptSocket("Bob", "test", id, frame -> {
            switch (frame.kind) {
                case DATA -> target.data(frame.sequence, frame.data);
                case CLOSE -> target.remoteClose();
                case RESET -> target.remoteReset();
                default -> {}
            }
        });
        byte[] expected = new byte[16 * 1024 * 1024];
        new Random(42).nextBytes(expected);
        var read = new FutureTask<byte[]>(() -> target.getInputStream().readAllBytes());
        Thread.ofVirtual().start(read);
        try {
            source.getOutputStream().write(expected);
            source.close();
            assertArrayEquals(expected, read.get(15, TimeUnit.SECONDS));
        } finally { source.remoteReset(); target.remoteReset(); }
    }
}
