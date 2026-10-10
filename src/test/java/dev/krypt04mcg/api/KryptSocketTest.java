package dev.krypt04mcg.api;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KryptSocketTest {
    /**
     * Verifies that stream boundaries half close and backpressure.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void streamBoundariesHalfCloseAndBackpressure() throws Exception {
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID());
        byte[] bytes = new byte[33000];
        socket.getOutputStream().write(bytes); bytes[0] = 99;
        assertEquals(0, socket.poll(16000)[0]);
        assertEquals(16000, socket.poll(16000).length);
        socket.close(); assertFalse(socket.needsEnd());
        assertEquals(1000, socket.poll(16000).length); assertTrue(socket.needsEnd());
        socket.endSent(); assertFalse(socket.isClosed());
        socket.accept(new byte[]{1, 2}); socket.accept(new byte[]{3}); socket.remoteEnd();
        assertArrayEquals(new byte[]{1, 2, 3}, socket.getInputStream().readAllBytes());
        assertTrue(socket.isClosed());
        assertThrows(IOException.class, () -> socket.getOutputStream().write(1));
    }
    /**
     * Verifies that failure wakes blocked read and does not become eof.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void failureWakesBlockedReadAndDoesNotBecomeEof() throws Exception {
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID());
        try (var executor = Executors.newSingleThreadExecutor()) {
            var blocked = executor.submit(() -> socket.getInputStream().read());
            socket.fail("Disconnected");
            var error = assertThrows(ExecutionException.class, () -> blocked.get(2, TimeUnit.SECONDS));
            assertInstanceOf(IOException.class, error.getCause());
        }
    }
    /**
     * Verifies that coalesces tiny writes and handles ring wrap.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void coalescesTinyWritesAndHandlesRingWrap() throws Exception {
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID());
        for (int i = 0; i < 5000; i++) socket.getOutputStream().write(i);
        byte[] first = socket.poll(4000);
        for (int i = 0; i < first.length; i++) assertEquals((byte) i, first[i]);
        for (int i = 5000; i < 10000; i++) socket.getOutputStream().write(i);
        byte[] next = socket.poll(16384); assertEquals(6000, next.length);
        for (int i = 0; i < next.length; i++) assertEquals((byte) (i + 4000), next[i]);
        socket.accept(first);
        byte[] consumed = socket.getInputStream().readNBytes(3000);
        assertEquals(3000, consumed.length);
        socket.accept(next); socket.remoteEnd();
        byte[] rest = socket.getInputStream().readAllBytes(); assertEquals(7000, rest.length);
        for (int i = 0; i < rest.length; i++) assertEquals((byte) (i + 3000), rest[i]);
    }
    /**
     * Verifies that queue limits do not partially accept writes.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void queueLimitsDoNotPartiallyAcceptWrites() throws Exception {
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID());
        assertThrows(IOException.class, () -> socket.getOutputStream().write(new byte[KryptSocket.MAX_BUFFERED_BYTES + 1]));
        assertNull(socket.poll(16384));
        socket.accept(new byte[KryptSocket.MAX_BUFFERED_BYTES]);
        assertThrows(IOException.class, () -> socket.accept(new byte[]{1}));
    }
}
