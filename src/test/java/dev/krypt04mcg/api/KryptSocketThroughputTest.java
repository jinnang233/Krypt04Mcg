package dev.krypt04mcg.api;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** In-memory regression harness: no Minecraft transport, crypto, clock, or stream ACK is involved. */
class KryptSocketThroughputTest {
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void transfersFourMiBByteForByteWithoutPerChunkStreamAckStalls() throws Exception {
        UUID id = UUID.randomUUID();
        RecordingTransport receiverOutbound = new RecordingTransport();
        KryptSocket receiver = new KryptSocket("Alice", "test:throughput", id, receiverOutbound);
        LoopbackTransport loopback = new LoopbackTransport(receiver);
        KryptSocket sender = new KryptSocket("Bob", "test:throughput", id, loopback);
        byte[] source = new byte[4 * 1024 * 1024];
        for (int i = 0; i < source.length; i++) source[i] = (byte) (i * 31 + i / 997);

        sender.getOutputStream().write(source);
        sender.close();

        assertArrayEquals(source, receiver.getInputStream().readAllBytes());
        assertEquals(source.length / KryptSocket.CHUNK_BYTES, loopback.dataFrames);
        assertEquals(1, loopback.closeFrames);
        assertTrue(receiverOutbound.frames.isEmpty(), "v2 receiver must not send stream ACK frames");
    }

    private static DataTransfer delivered() {
        UUID id = UUID.randomUUID();
        return new DataTransfer(id, CompletableFuture.completedFuture(
                new TransferResult(id, TransferResult.Status.DELIVERED)));
    }

    private static final class LoopbackTransport implements KryptSocket.Transport {
        private final KryptSocket target;
        int dataFrames;
        int closeFrames;

        LoopbackTransport(KryptSocket target) { this.target = target; }

        @Override public DataTransfer send(KryptStreamRegistry.Frame frame) {
            switch (frame.kind) {
                case DATA -> { dataFrames++; target.data(frame.sequence, frame.data); }
                case CLOSE -> { closeFrames++; target.remoteClose(); }
                case RESET -> target.remoteReset();
                default -> { }
            }
            return delivered();
        }
    }

    private static final class RecordingTransport implements KryptSocket.Transport {
        final Deque<KryptStreamRegistry.Frame> frames = new ArrayDeque<>();

        @Override public DataTransfer send(KryptStreamRegistry.Frame frame) {
            frames.addLast(frame);
            return delivered();
        }
    }
}
