package dev.krypt04mcg.api;

import static org.junit.jupiter.api.Assertions.*;
import dev.krypt04mcg.config.Krypt04McgConfig;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(20)
class KryptSocketTest {
    @Test void boundedReceiveWaitsInsteadOfResetAndReadReleasesCapacity() throws Exception {
        var config = new Krypt04McgConfig(); config.socketMaxBufferedMiB = 1;
        var socket = new KryptSocket("Bob", "test", UUID.randomUUID(), frame -> {}, config);
        try {
            for (int i = 0; i < 128; i++) socket.data(i, new byte[8192]);
            var blocked = new FutureTask<Void>(() -> { socket.data(128, new byte[8192]); return null; });
            Thread.ofVirtual().start(blocked);
            assertThrows(TimeoutException.class, () -> blocked.get(100, TimeUnit.MILLISECONDS));
            assertFalse(socket.isClosed());
            assertEquals(1024 * 1024, socket.state().bufferedIncomingBytes());
            socket.getInputStream().readNBytes(8192);
            blocked.get(2, TimeUnit.SECONDS);
            assertFalse(socket.isClosed());
            assertEquals(1024 * 1024, socket.state().bufferedIncomingBytes());
        } finally { socket.remoteReset(); }
    }

    @Test void outputBlocksUntilLocalTransportProgressWithoutReceipts() throws Exception {
        var config = new Krypt04McgConfig(); config.socketMaxBufferedMiB = 1;
        var gate = new CountDownLatch(1);
        var started = new CountDownLatch(1);
        var socket = new KryptSocket("Bob", "test", UUID.randomUUID(), frame -> {
            started.countDown();
            try { gate.await(); } catch (InterruptedException e) { throw new IOException(e); }
        }, config);
        var write = new FutureTask<Void>(() -> { socket.getOutputStream().write(new byte[2 * 1024 * 1024]); return null; });
        Thread.ofVirtual().start(write);
        try {
            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> write.get(100, TimeUnit.MILLISECONDS));
            assertTrue(socket.state().queuedChunks() <= 128);
            assertFalse(socket.isClosed());
            gate.countDown();
            write.get(3, TimeUnit.SECONDS);
        } finally { gate.countDown(); socket.remoteReset(); }
    }

    @Test void disconnectWakesBlockedWriterAndReader() throws Exception {
        var gate = new CountDownLatch(1);
        var socket = new KryptSocket("Bob", "test", UUID.randomUUID(), frame -> {
            try { gate.await(); } catch (InterruptedException e) { throw new IOException(e); }
        });
        var write = new FutureTask<Void>(() -> { socket.getOutputStream().write(new byte[8 * 1024 * 1024]); return null; });
        var read = new FutureTask<Integer>(() -> socket.getInputStream().read());
        Thread.ofVirtual().start(write); Thread.ofVirtual().start(read);
        assertThrows(TimeoutException.class, () -> write.get(100, TimeUnit.MILLISECONDS));
        socket.remoteReset();
        assertThrows(ExecutionException.class, () -> write.get(2, TimeUnit.SECONDS));
        assertThrows(ExecutionException.class, () -> read.get(2, TimeUnit.SECONDS));
        gate.countDown();
    }

    @Test void mainThreadIoIsRejectedBeforeWaitingForWriterMonitor() throws Exception {
        Thread main = Thread.currentThread();
        Krypt04McgApi.setMainThreadCheck(() -> Thread.currentThread() == main);
        var socket = new KryptSocket("Bob", "test", UUID.randomUUID(), frame -> {});
        try {
            assertThrows(IOException.class, () -> socket.getOutputStream().write(1));
            assertThrows(IOException.class, () -> socket.getInputStream().read());
            assertTimeout(java.time.Duration.ofMillis(100), socket::close);
        } finally { socket.remoteReset(); Krypt04McgApi.setMainThreadCheck(() -> false); }
    }

    @Test void strictOrderRejectsGapsAndInputCloseLeavesOutputUsable() throws Exception {
        var sent = new LinkedBlockingQueue<KryptStreamRegistry.Frame>();
        var socket = new KryptSocket("Bob", "test", UUID.randomUUID(), sent::add);
        socket.data(1, new byte[] {1});
        assertTrue(socket.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, sent.poll(2, TimeUnit.SECONDS).kind);
        var other = new KryptSocket("Bob", "test", UUID.randomUUID(), sent::add);
        try {
            other.getInputStream().close();
            other.data(0, new byte[] {1});
            other.getOutputStream().write(2);
            assertEquals(KryptStreamRegistry.Kind.DATA, sent.poll(2, TimeUnit.SECONDS).kind);
            assertEquals(0, other.state().bufferedIncomingBytes());
            assertFalse(other.isClosed());
        } finally { other.remoteReset(); }
    }

    @Test void flushWaitsForLocalWriteAndPeerClosePreservesUnreadBytes() throws Exception {
        var gate = new CountDownLatch(1);
        var socket = new KryptSocket("Bob", "test", UUID.randomUUID(), frame -> {
            try { gate.await(); } catch (InterruptedException e) { throw new IOException(e); }
        });
        try {
            socket.getOutputStream().write(42);
            var flush = new FutureTask<Void>(() -> { socket.getOutputStream().flush(); return null; });
            Thread.ofVirtual().start(flush);
            assertThrows(TimeoutException.class, () -> flush.get(100, TimeUnit.MILLISECONDS));
            gate.countDown(); flush.get(2, TimeUnit.SECONDS);
            socket.data(0, new byte[] {7, 8});
            socket.remoteClose();
            assertTrue(socket.isClosed());
            assertArrayEquals(new byte[] {7, 8}, socket.getInputStream().readAllBytes());
            assertThrows(IOException.class, () -> socket.getOutputStream().write(1));
        } finally { gate.countDown(); socket.remoteReset(); }
    }
}
