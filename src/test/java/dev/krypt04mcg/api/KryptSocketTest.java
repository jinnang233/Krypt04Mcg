package dev.krypt04mcg.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class KryptSocketTest {
    @Test void frameCodecRejectsMalformedInputAndRoundTripsBinaryData() {
        UUID id = UUID.randomUUID();
        byte[] data = new byte[] {0, -1, 42};
        var decoded = KryptStreamRegistry.Frame.decode(KryptStreamRegistry.Frame.data(id, 17, data).encode());
        assertEquals(KryptStreamRegistry.Kind.DATA, decoded.kind);
        assertEquals(id, decoded.streamId);
        assertEquals(17, decoded.sequence);
        assertArrayEquals(data, decoded.data);
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(new byte[] {1}));
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(
                Arrays.copyOf(KryptStreamRegistry.Frame.close(id).encode(), 20)));
    }

    @Test void chunksFlowThroughWindowInOrderAndCloseAfterFinalAck() throws Exception {
        UUID id = UUID.randomUUID();
        Deque<KryptStreamRegistry.Frame> leftWire = new ArrayDeque<>();
        Deque<KryptStreamRegistry.Frame> rightWire = new ArrayDeque<>();
        KryptSocket left = new KryptSocket("Bob", "test:stream", id, leftWire::addLast);
        KryptSocket right = new KryptSocket("Alice", "test:stream", id, rightWire::addLast);
        byte[] source = new byte[KryptSocket.CHUNK_BYTES * 6 + 31];
        for (int i = 0; i < source.length; i++) source[i] = (byte) i;

        left.getOutputStream().write(source);
        assertEquals(KryptSocket.WINDOW_CHUNKS, leftWire.size());
        left.close();

        while (!leftWire.isEmpty() || !rightWire.isEmpty()) {
            while (!leftWire.isEmpty()) deliver(leftWire.removeFirst(), right);
            while (!rightWire.isEmpty()) deliver(rightWire.removeFirst(), left);
        }

        var received = new ByteArrayOutputStream();
        byte[] buffer = new byte[7000];
        while (received.size() < source.length) {
            int count = right.getInputStream().read(buffer);
            assertTrue(count > 0);
            received.write(buffer, 0, count);
        }
        assertArrayEquals(source, received.toByteArray());
        assertEquals(-1, right.getInputStream().read());
        assertTrue(left.isClosed());
    }

    @Test void boundsQueuedWritesAndResetsOnOutOfOrderData() throws Exception {
        UUID id = UUID.randomUUID();
        Deque<KryptStreamRegistry.Frame> wire = new ArrayDeque<>();
        KryptSocket socket = new KryptSocket("Bob", "test:stream", id, wire::addLast);
        assertThrows(java.io.IOException.class,
                () -> socket.getOutputStream().write(new byte[KryptSocket.MAX_BUFFERED_BYTES + 1]));

        KryptSocket receiver = new KryptSocket("Alice", "test:stream", id, wire::addLast);
        receiver.data(1, new byte[] {1});
        assertTrue(receiver.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, wire.getLast().kind);
    }

    @Test void configuredBufferAndWindowApplyToWritesAndLiveChanges() throws Exception {
        var config = new dev.krypt04mcg.config.Krypt04McgConfig();
        config.socketMaxBufferedMiB = 2;
        config.socketWindowChunks = 1;
        Deque<KryptStreamRegistry.Frame> wire = new ArrayDeque<>();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), wire::addLast, config);
        socket.getOutputStream().write(new byte[2 * 1024 * 1024]);
        assertEquals(1, wire.size());
        socket.getOutputStream().write(new byte[KryptSocket.CHUNK_BYTES]);
        assertThrows(java.io.IOException.class, () -> socket.getOutputStream().write(1));
        assertEquals(1, wire.size());
        config.socketWindowChunks = 3;
        socket.ack(0);
        assertEquals(4, wire.size());
        config.socketWindowChunks = 1;
        socket.ack(1);
        socket.ack(2);
        assertEquals(4, wire.size());
        socket.ack(3);
        assertEquals(5, wire.size());
        config.socketMaxBufferedMiB = 1;
        assertThrows(java.io.IOException.class, () -> socket.getOutputStream().write(1));
        config.socketMaxBufferedMiB = 3;
        assertDoesNotThrow(() -> socket.getOutputStream().write(1));
    }

    @Test void configuredIncomingLimitReleasesCapacityAfterReads() throws Exception {
        var config = new dev.krypt04mcg.config.Krypt04McgConfig();
        config.socketMaxBufferedMiB = 2;
        Deque<KryptStreamRegistry.Frame> wire = new ArrayDeque<>();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), wire::addLast, config);
        int chunks = 2 * 1024 * 1024 / KryptSocket.CHUNK_BYTES;
        for (int i = 0; i < chunks; i++) socket.data(i, new byte[KryptSocket.CHUNK_BYTES]);
        assertFalse(socket.isClosed());
        assertEquals(chunks, wire.size());
        assertEquals(0, socket.getInputStream().read());
        socket.data(chunks, new byte[] {42});
        assertFalse(socket.isClosed());
        socket.data(chunks + 1, new byte[] {43});
        assertTrue(socket.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, wire.getLast().kind);
    }

    private static void deliver(KryptStreamRegistry.Frame frame, KryptSocket target) {
        switch (frame.kind) {
            case DATA -> target.data(frame.sequence, frame.data);
            case ACK -> target.ack(frame.sequence);
            case CLOSE -> target.remoteClose();
            case RESET -> target.remoteReset();
            default -> { }
        }
    }
}
