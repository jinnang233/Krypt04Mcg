package dev.krypt04mcg.service;

import static org.junit.jupiter.api.Assertions.*;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.DataPayload;
import dev.krypt04mcg.util.JsonSupport;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KryptSocketDataTransferIntegrationTest {
    private static final String CHANNEL = "integration:stream";
    private static final int CHUNK = 128 * 1024;
    @TempDir Path root;

    @ParameterizedTest(name = "{0} MiB")
    @ValueSource(ints = {4, 16, 64})
    @Timeout(value = 240, unit = TimeUnit.SECONDS)
    void transfersMultiMiBThroughRealEncryptedFragmentedServices(int mebibytes) throws Exception {
        try (var pair = new StreamPair()) {
            pair.config.maxMessagesPerSession = 1;
            pair.config.rotateAfterBytes = 1;
            SocketPair sockets = pair.open();
            byte[] source = pattern(mebibytes * 1024 * 1024, 17 + mebibytes);
            CompletableFuture<byte[]> received = readExactlyAsync(sockets.remote(), source.length);

            pair.write(source, sockets.local().getOutputStream());
            pair.pumpUntil(() -> received.isDone() && pair.alice.pipelineStats().pending() == 0);
            assertArrayEquals(source, received.join());
            sockets.local().close();
            pair.pumpUntil(() -> sockets.remote().isClosed() && pair.alice.pipelineStats().pending() == 0);

            SessionRecord session = pair.aliceSessions.find("Bob").orElseThrow();
            assertEquals(0, session.messageCount());
            assertEquals(0, session.bytesUsed());
            assertTrue(session.apiBytesUsed() >= source.length);
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.local()).queuedChunks());
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.local()).inFlightChunks());
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.remote()).bufferedIncomingBytes());
            assertEquals(new DataTransferService.PipelineStats(0, 0, 0, 0, 0, 0), pair.alice.pipelineStats());
            assertEquals(new DataTransferService.PipelineStats(0, 0, 0, 0, 0, 0), pair.bob.pipelineStats());
        }
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void fullDuplexTransfersFourMiBEachDirection() throws Exception {
        try (var pair = new StreamPair()) {
            SocketPair sockets = pair.open();
            byte[] left = pattern(4 * 1024 * 1024, 41);
            byte[] right = pattern(4 * 1024 * 1024, 83);
            CompletableFuture<byte[]> atRemote = readExactlyAsync(sockets.remote(), left.length);
            CompletableFuture<byte[]> atLocal = readExactlyAsync(sockets.local(), right.length);
            int leftOffset = 0, rightOffset = 0;
            while (leftOffset < left.length || rightOffset < right.length) {
                if (leftOffset < left.length)
                    leftOffset += pair.tryWrite(left, leftOffset, sockets.local().getOutputStream());
                if (rightOffset < right.length)
                    rightOffset += pair.tryWrite(right, rightOffset, sockets.remote().getOutputStream());
                pair.tick();
            }
            pair.pumpUntil(() -> atRemote.isDone() && atLocal.isDone()
                    && pair.alice.pipelineStats().pending() == 0 && pair.bob.pipelineStats().pending() == 0);
            assertArrayEquals(left, atRemote.join());
            assertArrayEquals(right, atLocal.join());
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.local()).bufferedIncomingBytes());
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.remote()).bufferedIncomingBytes());
            sockets.local().close();
            sockets.remote().close();
            pair.pumpUntil(() -> pair.alice.pipelineStats().pending() == 0 && pair.bob.pipelineStats().pending() == 0);
        }
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void delayedOutOfOrderAcksFillBothSocketAndTransferWindows() throws Exception {
        try (var pair = new StreamPair()) {
            SocketPair sockets = pair.open();
            byte[] source = pattern(4 * CHUNK, 109);
            CompletableFuture<byte[]> received = readExactlyAsync(sockets.remote(), source.length);
            pair.holdBob = true;
            pair.write(source, sockets.local().getOutputStream());
            pair.pumpUntil(() -> pair.alice.pipelineStats().waitingAck() == 4);

            assertEquals(4, KryptStreamTestEndpoint.stats(sockets.local()).inFlightChunks());
            assertEquals(4, pair.alice.pipelineStats().pending());
            assertEquals(4, pair.alice.pipelineStats().waitingAck());
            pair.releaseBobEnvelopesInReverse();
            pair.pumpUntil(() -> received.isDone() && pair.alice.pipelineStats().pending() == 0);
            assertArrayEquals(source, received.join());
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.local()).inFlightChunks());
            assertEquals(new DataTransferService.PipelineStats(0, 0, 0, 0, 0, 0), pair.bob.pipelineStats());
        }
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void streamDataFramesMayArriveOutOfOrderWithoutResettingTheSocket() throws Exception {
        try (var pair = new StreamPair()) {
            SocketPair sockets = pair.open();
            byte[] source = pattern(3 * 1024, 127);
            CompletableFuture<byte[]> received = readExactlyAsync(sockets.remote(), source.length);
            pair.holdAlice = true;
            for (int offset = 0; offset < source.length; offset += 1024)
                sockets.local().getOutputStream().write(source, offset, 1024);
            pair.pumpUntil(() -> pair.heldAliceEnvelopeCount() == 3);

            pair.releaseAliceEnvelopes(0, 2, 1);
            pair.pumpUntil(() -> received.isDone() && pair.alice.pipelineStats().pending() == 0);

            assertArrayEquals(source, received.join());
            assertFalse(sockets.local().isClosed());
            assertFalse(sockets.remote().isClosed());
            assertEquals(0, KryptStreamTestEndpoint.stats(sockets.remote()).reorderedIncomingChunks());
        }
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void lostDataTransferTimesOutOnlyItsSocketAndReleasesPipelineState() throws Exception {
        try (var pair = new StreamPair()) {
            pair.config.maxDataAttempts = 1;
            SocketPair sockets = pair.open();
            pair.dropNextAliceEnvelope = true;
            sockets.local().getOutputStream().write(pattern(CHUNK, 7));
            pair.pumpUntil(() -> pair.alice.pipelineStats().waitingAck() == 1);
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            pair.pumpUntil(sockets.local()::isClosed);
            pair.pumpUntil(() -> pair.alice.pipelineStats().pending() == 0);
            assertEquals(new DataTransferService.PipelineStats(0, 0, 0, 0, 0, 0), pair.alice.pipelineStats());
        }
    }

    private static byte[] pattern(int size, int seed) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) bytes[i] = (byte) (i * 31 + i / 997 + seed);
        return bytes;
    }

    private static CompletableFuture<byte[]> readExactlyAsync(KryptSocket socket, int size) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                byte[] result = new byte[size];
                InputStream input = socket.getInputStream();
                int offset = 0;
                while (offset < size) {
                    int count = input.read(result, offset, size - offset);
                    if (count < 0) throw new AssertionError("Unexpected stream EOF at " + offset + " of " + size);
                    offset += count;
                }
                return result;
            } catch (Exception e) { throw new CompletionException(e); }
        });
    }

    private record SocketPair(KryptSocket local, KryptSocket remote) {}

    private final class StreamPair implements AutoCloseable {
        final AtomicLong now = new AtomicLong(System.currentTimeMillis());
        final Krypt04McgConfig config = new Krypt04McgConfig();
        final KeyStoreService aliceKeys, bobKeys;
        final SessionService aliceSessions, bobSessions;
        final SessionHandshakeService aliceHandshake, bobHandshake;
        final DataTransferService alice, bob;
        final KryptStreamTestEndpoint aliceStreams = new KryptStreamTestEndpoint();
        final KryptStreamTestEndpoint bobStreams = new KryptStreamTestEndpoint();
        final List<DataPayload> heldAlice = new ArrayList<>(), heldBob = new ArrayList<>();
        boolean holdAlice, holdBob, dropNextAliceEnvelope;
        String droppedAliceEnvelope;

        StreamPair() throws Exception {
            var crypto = new CryptoService();
            aliceKeys = new KeyStoreService(root.resolve("alice"), crypto);
            bobKeys = new KeyStoreService(root.resolve("bob"), crypto);
            aliceKeys.init("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
            bobKeys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
            aliceKeys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(bobKeys.ownPublicIdentity()));
            bobKeys.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(aliceKeys.ownPublicIdentity()));
            config.enableDataApi = true;
            config.apiReceiver = "Bob";
            config.maxDataQueuedMiB = 16;
            config.socketMaxBufferedMiB = 4;
            config.socketWindowChunks = 4;
            config.dataTransferWindow = 4;
            config.apiMaxMessagesPerSession = 65536;
            config.apiRotateAfterBytes = 1024L * 1024L * 1024L;
            aliceSessions = new SessionService(root.resolve("alice"));
            bobSessions = new SessionService(root.resolve("bob"));
            aliceHandshake = new SessionHandshakeService(crypto, aliceSessions);
            bobHandshake = new SessionHandshakeService(crypto, bobSessions);
            exchange();
            alice = new DataTransferService(config, aliceKeys, new KeyTrustService(root.resolve("alice")),
                    aliceSessions, aliceHandshake, () -> true, this::fromAlice, now::get);
            bob = new DataTransferService(config, bobKeys, new KeyTrustService(root.resolve("bob")),
                    bobSessions, bobHandshake, () -> true, this::fromBob, now::get);
            Krypt04McgApi.initialize((player, channel, bytes) -> { throw new AssertionError("unused sender"); },
                    player -> player.equalsIgnoreCase("Alice") ? bob.connect("Alice") : alice.connect("Bob"), config);
        }

        SocketPair open() throws Exception {
            AtomicReference<KryptSocket> remote = new AtomicReference<>();
            bobStreams.listen(CHANNEL, remote::set);
            KryptSocket local = aliceStreams.connect(alice.connect("Bob"), CHANNEL);
            Krypt04McgApi.registerReceiver(KryptStreamTestEndpoint.wireChannel(), (sender, bytes) -> {
                if (sender.equalsIgnoreCase("Alice")) bobStreams.receive(sender, bytes);
                else aliceStreams.receive(sender, bytes);
            });
            pumpUntil(() -> remote.get() != null && alice.pipelineStats().pending() == 0);
            return new SocketPair(local, remote.get());
        }

        void exchange() throws Exception {
            var request = aliceHandshake.begin(bobKeys.ownPublicIdentity(), aliceKeys.local(),
                    KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            var response = new AtomicReference<EncryptedPacket>();
            bobHandshake.complete(request, bobHandshake.decrypt(request, bobKeys.local(), aliceKeys.ownPublicIdentity()),
                    aliceKeys.ownPublicIdentity(), bobKeys.local(), false, AeadAlgorithm.AES_256_GCM,
                    (packet, peer) -> response.set(packet));
            aliceHandshake.complete(response.get(), aliceHandshake.decrypt(response.get(), aliceKeys.local(), bobKeys.ownPublicIdentity()),
                    bobKeys.ownPublicIdentity(), aliceKeys.local(), false, AeadAlgorithm.AES_256_GCM,
                    (packet, peer) -> fail("Unexpected response"));
        }

        void fromAlice(DataPayload payload) {
            String envelope = payload.fragment().split(":", 2)[0];
            if (dropNextAliceEnvelope && droppedAliceEnvelope == null) droppedAliceEnvelope = envelope;
            if (envelope.equals(droppedAliceEnvelope)) return;
            if (holdAlice) heldAlice.add(payload);
            else bob.receive(new DataPayload("Alice", payload.fragment(), 1));
        }

        void fromBob(DataPayload payload) {
            if (holdBob) heldBob.add(payload);
            else alice.receive(new DataPayload("Bob", payload.fragment(), 1));
        }

        void releaseBobEnvelopesInReverse() {
            Map<String, List<DataPayload>> grouped = new LinkedHashMap<>();
            for (DataPayload payload : heldBob)
                grouped.computeIfAbsent(payload.fragment().split(":", 2)[0], ignored -> new ArrayList<>()).add(payload);
            List<List<DataPayload>> envelopes = new ArrayList<>(grouped.values());
            Collections.reverse(envelopes);
            holdBob = false;
            heldBob.clear();
            for (List<DataPayload> envelope : envelopes)
                for (DataPayload payload : envelope) alice.receive(new DataPayload("Bob", payload.fragment(), 1));
        }

        int heldAliceEnvelopeCount() { return grouped(heldAlice).size(); }

        void releaseAliceEnvelopes(int... order) {
            List<List<DataPayload>> envelopes = new ArrayList<>(grouped(heldAlice).values());
            assertEquals(envelopes.size(), order.length);
            holdAlice = false;
            heldAlice.clear();
            for (int index : order)
                for (DataPayload payload : envelopes.get(index)) bob.receive(new DataPayload("Alice", payload.fragment(), 1));
        }

        private Map<String, List<DataPayload>> grouped(List<DataPayload> payloads) {
            Map<String, List<DataPayload>> grouped = new LinkedHashMap<>();
            for (DataPayload payload : payloads)
                grouped.computeIfAbsent(payload.fragment().split(":", 2)[0], ignored -> new ArrayList<>()).add(payload);
            return grouped;
        }

        void write(byte[] source, OutputStream output) throws Exception {
            int offset = 0;
            while (offset < source.length) {
                offset += tryWrite(source, offset, output);
                tick();
            }
        }

        int tryWrite(byte[] source, int offset, OutputStream output) throws Exception {
            int count = Math.min(CHUNK, source.length - offset);
            try {
                output.write(source, offset, count);
                return count;
            } catch (java.io.IOException e) {
                if (!"KryptSocket backpressure".equals(e.getMessage())) throw e;
                return 0;
            }
        }

        void tick() throws Exception {
            alice.tick();
            bob.tick();
            Thread.sleep(1);
        }

        void pumpUntil(BooleanSupplier condition) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(220);
            while (!condition.getAsBoolean() && System.nanoTime() < deadline) tick();
            assertTrue(condition.getAsBoolean(), "Integrated transport did not reach expected state: alice="
                    + alice.pipelineStats() + ", bob=" + bob.pipelineStats());
        }

        @Override public void close() {
            alice.close();
            bob.close();
            aliceHandshake.close();
            bobHandshake.close();
            Krypt04McgApi.unregisterReceiver(KryptStreamTestEndpoint.wireChannel());
            Krypt04McgApi.unregisterSocketReceiver(CHANNEL);
        }
    }
}
