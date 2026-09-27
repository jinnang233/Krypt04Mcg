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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class KryptSocketTest {
    @Test void frameCodecRejectsMalformedInputAndRoundTripsBinaryData() {
        UUID id = UUID.randomUUID();
        byte[] data = new byte[KryptSocket.CHUNK_BYTES];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        var decoded = KryptStreamRegistry.Frame.decode(KryptStreamRegistry.Frame.data(id, 17, data).encode());
        assertEquals(KryptStreamRegistry.Kind.DATA, decoded.kind);
        assertEquals(id, decoded.streamId);
        assertEquals(17, decoded.sequence);
        assertArrayEquals(data, decoded.data);
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(new byte[] {2}));
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(
                Arrays.copyOf(KryptStreamRegistry.Frame.close(id).encode(), 20)));
    }

    @Test void frameCodecRejectsDataLargerThan128KiB() {
        UUID id = UUID.randomUUID();
        byte[] encoded = KryptStreamRegistry.Frame.data(id, 0, new byte[KryptSocket.CHUNK_BYTES + 1]).encode();
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(encoded));
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

    @Test void boundsQueuedWritesAndResetsBeyondReorderWindow() throws Exception {
        UUID id = UUID.randomUUID();
        TestTransport transport = new TestTransport();
        KryptSocket socket = new KryptSocket("Bob", "test:stream", id, transport);
        assertThrows(java.io.IOException.class,
                () -> socket.getOutputStream().write(new byte[KryptSocket.MAX_BUFFERED_BYTES + 1]));

        KryptSocket receiver = new KryptSocket("Alice", "test:stream", id, transport);
        receiver.data(4, new byte[] {1});
        assertTrue(receiver.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, transport.frames.getLast().kind);
    }

    @Test void reordersDataFramesAndDeliversDuplicatesOnlyOnce() throws Exception {
        var config = new Krypt04McgConfig();
        config.socketWindowChunks = 4;
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport, config);

        socket.data(0, new byte[] {0});
        socket.data(2, new byte[] {2});
        socket.data(2, new byte[] {99});
        socket.data(1, new byte[] {1});
        socket.data(1, new byte[] {98});

        assertFalse(socket.isClosed());
        assertEquals(0, socket.state().reorderedIncomingChunks());
        assertArrayEquals(new byte[] {0, 1, 2}, socket.getInputStream().readNBytes(3));
        assertTrue(transport.frames.isEmpty());
    }

    @Test void resetClearsReorderedData() {
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), new TestTransport());
        socket.data(2, new byte[KryptSocket.CHUNK_BYTES]);
        assertEquals(1, socket.state().reorderedIncomingChunks());
        assertEquals(KryptSocket.CHUNK_BYTES, socket.state().bufferedIncomingBytes());
        socket.remoteReset();
        assertEquals(0, socket.state().reorderedIncomingChunks());
        assertEquals(0, socket.state().bufferedIncomingBytes());
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

    @Test void closeWaitsForEverySubmittedDataCompletionIncludingOutOfOrderResults() throws Exception {
        var config = new Krypt04McgConfig();
        config.socketWindowChunks = 4;
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport, config);
        socket.getOutputStream().write(new byte[KryptSocket.CHUNK_BYTES * 3]);
        assertEquals(3, socket.state().inFlightChunks());
        socket.close();

        transport.complete(2, TransferResult.Status.DELIVERED);
        assertEquals(3, socket.state().inFlightChunks());
        assertEquals(1, socket.state().completedOutOfOrderChunks());
        transport.complete(0, TransferResult.Status.DELIVERED);
        assertTrue(transport.frames.stream().noneMatch(frame -> frame.kind == KryptStreamRegistry.Kind.CLOSE));
        transport.complete(1, TransferResult.Status.DELIVERED);
        assertEquals(0, socket.state().inFlightChunks());
        assertEquals(KryptStreamRegistry.Kind.CLOSE, transport.frames.getLast().kind);
    }

    @Test void localCloseReleasesUnreadInputAndReportsEof() throws Exception {
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport);
        socket.data(0, new byte[KryptSocket.CHUNK_BYTES]);
        socket.close();
        assertEquals(-1, socket.getInputStream().read());
        assertEquals(KryptStreamRegistry.Kind.CLOSE, transport.frames.getLast().kind);
    }

    @Test void closingInputDoesNotResetOrCloseTheOutputDirection() throws Exception {
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport);
        socket.data(2, new byte[] {2});
        socket.getInputStream().close();
        socket.data(0, new byte[] {0});
        socket.data(1, new byte[] {1});
        assertThrows(java.io.IOException.class, () -> socket.getInputStream().read());
        assertDoesNotThrow(() -> socket.getOutputStream().write(7));
        assertFalse(socket.isClosed());
        assertEquals(0, socket.state().reorderedIncomingChunks());
        assertEquals(0, socket.state().bufferedIncomingBytes());
        assertTrue(transport.frames.stream().noneMatch(frame -> frame.kind == KryptStreamRegistry.Kind.RESET));
    }

    @Test void failureAndResetReleasePendingStateAndDoNotLeakLaterCompletions() throws Exception {
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport);
        socket.getOutputStream().write(new byte[KryptSocket.CHUNK_BYTES * 5]);

        transport.complete(1, TransferResult.Status.DELIVERED);
        transport.complete(0, TransferResult.Status.TIMEOUT);
        assertTrue(socket.isClosed());
        assertEquals(1, transport.frames.stream().filter(frame -> frame.kind == KryptStreamRegistry.Kind.RESET).count());
        transport.complete(2, TransferResult.Status.DELIVERED);
        transport.complete(3, TransferResult.Status.REJECTED);
        assertEquals(1, transport.frames.stream().filter(frame -> frame.kind == KryptStreamRegistry.Kind.RESET).count());
        assertThrows(java.io.IOException.class, () -> socket.getOutputStream().write(1));

        var remoteReset = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), new TestTransport());
        remoteReset.data(0, new byte[] {1, 2, 3});
        remoteReset.remoteReset();
        assertThrows(java.io.IOException.class, () -> remoteReset.getInputStream().read());
    }

    @ParameterizedTest
    @EnumSource(value = TransferResult.Status.class, names = "DELIVERED", mode = EnumSource.Mode.EXCLUDE)
    void everyDataTransferFailureStatusResetsSocket(TransferResult.Status status) throws Exception {
        TestTransport transport = new TestTransport();
        var socket = new KryptSocket("Bob", "test:stream", UUID.randomUUID(), transport);
        socket.getOutputStream().write(new byte[] {1});
        transport.complete(0, status);
        assertTrue(socket.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, transport.frames.getLast().kind);
    }

    @Test void registryResetsUnknownStreamsWrongPeersAndMalformedKnownFrames() {
        Map<String, Deque<KryptStreamRegistry.Frame>> sent = new HashMap<>();
        java.util.function.Function<String, KryptSession> sessions = peer -> recordingSession(peer,
                sent.computeIfAbsent(peer, ignored -> new ArrayDeque<>()));
        Krypt04McgApi.initialize((player, channel, data) -> completedTransfer(TransferResult.Status.DELIVERED), sessions);
        KryptStreamRegistry registry = new KryptStreamRegistry();
        Deque<KryptStreamRegistry.Frame> bobFrames = sent.computeIfAbsent("Bob", ignored -> new ArrayDeque<>());
        KryptSocket socket = registry.connect(sessions.apply("Bob"), "test:stream");
        bobFrames.clear();

        registry.receive("Mallory", KryptStreamRegistry.Frame.close(socket.streamId()).encode());
        assertTrue(socket.isClosed());
        assertEquals(KryptStreamRegistry.Kind.RESET, bobFrames.getLast().kind);
        assertEquals(KryptStreamRegistry.Kind.RESET, sent.get("Mallory").getLast().kind);

        UUID unknown = UUID.randomUUID();
        registry.receive("Alice", KryptStreamRegistry.Frame.close(unknown).encode());
        assertEquals(unknown, sent.get("Alice").getLast().streamId);

        UUID malformed = UUID.randomUUID();
        byte[] oversized = KryptStreamRegistry.Frame.data(malformed, 0, new byte[] {1}).encode();
        oversized[26] = 0x00;
        oversized[27] = 0x02;
        oversized[28] = 0x00;
        oversized[29] = 0x01;
        registry.receive("Alice", oversized);
        assertEquals(malformed, sent.get("Alice").getLast().streamId);
        assertEquals(KryptStreamRegistry.Kind.RESET, sent.get("Alice").getLast().kind);
    }

    private static KryptSession recordingSession(String peer, Deque<KryptStreamRegistry.Frame> sent) {
        return new KryptSession(peer, CompletableFuture.completedFuture("ready"), (channel, bytes) -> {
            sent.addLast(KryptStreamRegistry.Frame.decode(bytes));
            return completedTransfer(TransferResult.Status.DELIVERED);
        }, () -> { }, () -> true);
    }

    private static DataTransfer completedTransfer(TransferResult.Status status) {
        UUID id = UUID.randomUUID();
        return new DataTransfer(id, CompletableFuture.completedFuture(new TransferResult(id, status)));
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
