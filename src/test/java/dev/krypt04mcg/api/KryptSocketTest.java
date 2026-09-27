package dev.krypt04mcg.api;

import static org.junit.jupiter.api.Assertions.*;

import dev.krypt04mcg.config.Krypt04McgConfig;
import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
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
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(new byte[] {2}));
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(
                Arrays.copyOf(KryptStreamRegistry.Frame.close(id).encode(), 20)));
    }

    @Test void chunksFlowThroughWindowInOrderAndCloseAfterFinalCompletion() throws Exception {
        UUID id = UUID.randomUUID();
        TestTransport transport = new TestTransport();
        KryptSocket left = new KryptSocket("Bob", "test:stream", id, transport);
        KryptSocket right = new KryptSocket("Alice", "test:stream", id, new TestTransport());
        byte[] source = new byte[KryptSocket.CHUNK_BYTES * 6 + 31];
        for (int i = 0; i < source.length; i++) source[i] = (byte) i;

        left.getOutputStream().write(source);
        assertEquals(KryptSocket.WINDOW_CHUNKS, transport.frames.size());
        left.close();

        while (!transport.frames.isEmpty()) {
            KryptStreamRegistry.Frame frame = transport.frames.removeFirst();
            if (frame.kind == KryptStreamRegistry.Kind.DATA) {
                right.data(frame.sequence, frame.data);
                transport.complete(frame.sequence, TransferResult.Status.DELIVERED);
            } else if (frame.kind == KryptStreamRegistry.Kind.CLOSE) right.remoteClose();
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
        TestTransport transport = new TestTransport();
        KryptSocket socket = new KryptSocket("Bob", "test:stream", id, transport);
        assertThrows(java.io.IOException.class,
                () -> socket.getOutputStream().write(new byte[KryptSocket.MAX_BUFFERED_BYTES + 1]));

        KryptSocket receiver = new KryptSocket("Alice", "test:stream", id, transport);
        receiver.data(1, new byte[] {1});
        assertTrue(receiver.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, transport.frames.getLast().kind);
    }

    @Test void configuredBufferAndWindowApplyToWritesAndLiveChanges() throws Exception {
        var config = new Krypt04McgConfig();
        config.socketMaxBufferedMiB = 2;
        config.socketWindowChunks = 1;
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport, config);
        socket.getOutputStream().write(new byte[2 * 1024 * 1024]);
        assertEquals(1, transport.frames.size());
        socket.getOutputStream().write(new byte[KryptSocket.CHUNK_BYTES]);
        assertThrows(java.io.IOException.class, () -> socket.getOutputStream().write(1));
        assertEquals(1, transport.frames.size());
        config.socketWindowChunks = 3;
        transport.complete(0, TransferResult.Status.DELIVERED);
        assertEquals(4, transport.frames.size());
        config.socketWindowChunks = 1;
        transport.complete(1, TransferResult.Status.DELIVERED);
        transport.complete(2, TransferResult.Status.DELIVERED);
        assertEquals(4, transport.frames.size());
        transport.complete(3, TransferResult.Status.DELIVERED);
        assertEquals(5, transport.frames.size());
        config.socketMaxBufferedMiB = 1;
        assertThrows(java.io.IOException.class, () -> socket.getOutputStream().write(1));
        config.socketMaxBufferedMiB = 3;
        assertDoesNotThrow(() -> socket.getOutputStream().write(1));
    }

    @Test void configuredIncomingLimitReleasesCapacityAfterReadsWithoutSendingAck() throws Exception {
        var config = new Krypt04McgConfig();
        config.socketMaxBufferedMiB = 2;
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport, config);
        int chunks = 2 * 1024 * 1024 / KryptSocket.CHUNK_BYTES;
        for (int i = 0; i < chunks; i++) socket.data(i, new byte[KryptSocket.CHUNK_BYTES]);
        assertFalse(socket.isClosed());
        assertTrue(transport.frames.isEmpty());
        assertEquals(0, socket.getInputStream().read());
        socket.data(chunks, new byte[] {42});
        assertFalse(socket.isClosed());
        socket.data(chunks + 1, new byte[] {43});
        assertTrue(socket.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, transport.frames.getLast().kind);
    }

    private static final class TestTransport implements KryptSocket.Transport {
        final Deque<KryptStreamRegistry.Frame> frames = new ArrayDeque<>();
        final Map<Long, CompletableFuture<TransferResult>> dataCompletions = new HashMap<>();

        @Override public DataTransfer send(KryptStreamRegistry.Frame frame) {
            frames.addLast(frame);
            var completion = new CompletableFuture<TransferResult>();
            var transfer = new DataTransfer(UUID.randomUUID(), completion);
            if (frame.kind == KryptStreamRegistry.Kind.DATA) dataCompletions.put(frame.sequence, completion);
            else completion.complete(new TransferResult(transfer.transferId(), TransferResult.Status.DELIVERED));
            return transfer;
        }

        void complete(long sequence, TransferResult.Status status) {
            var completion = dataCompletions.remove(sequence);
            assertNotNull(completion, "missing DATA completion " + sequence);
            completion.complete(new TransferResult(UUID.randomUUID(), status));
        }
    }
}
