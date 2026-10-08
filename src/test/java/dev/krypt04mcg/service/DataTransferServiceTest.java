package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.channel.*;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.util.JsonSupport;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class DataTransferServiceTest {
    @TempDir Path root;
    static final String CHANNEL = "test:stream";
    @Test void simultaneousApiHandshakeConvergesAndCanRotateAgain() throws Exception {
        try (var pair = new Pair()) {
            var alice = pair.alice.connect("Bob");
            var bob = pair.bob.connect("Alice");
            pair.until(() -> alice.isReady() && bob.isReady());
            var as = new SessionService(root.resolve("alice-api"));
            var bs = new SessionService(root.resolve("bob-api"));
            assertEquals(as.find("Bob").orElseThrow().secret(), bs.find("Alice").orElseThrow().secret());
            String epoch = as.find("Bob").orElseThrow().sessionId();
            pair.alice.clear(); pair.bob.clear();
            as.clear("Bob"); bs.clear("Alice");
            var rotated = pair.alice.connect("Bob");
            pair.until(rotated::isReady);
            assertNotEquals(epoch, rotated.sessionId());
            assertEquals(as.find("Bob").orElseThrow().secret(), bs.find("Alice").orElseThrow().secret());
        }
    }

    @Test void disconnectBeforeDecryptionCompletionDoesNotConsumeRequest() throws Exception {
        try (var pair = new Pair()) {
            pair.alice.connect("Bob");
            pair.until(() -> !pair.controls.isEmpty());
            pair.bob.tick(); // submit decrypt; its commit callback has not run yet
            assertTrue(exchangeWorker(pair.bob).busy());
            pair.bob.clear();
            pair.until(() -> !exchangeWorker(pair.bob).busy());
            var sessions = new SessionService(root.resolve("bob-api"));
            assertTrue(sessions.find("Alice").isEmpty());
            pair.bob.receive(pair.controls.getFirst().routed("Alice", ControlPayload.Kind.EXCHANGE, -1));
            pair.bob.tick();
            pair.until(() -> !exchangeWorker(pair.bob).busy());
            assertTrue(sessions.find("Alice").isPresent());
        }
    }
    @Test void handshakeTimeoutRejectsLateResponseAndAllowsRenegotiation() throws Exception {
        try (var pair = new Pair()) {
            pair.dropResponse = true;
            var first = pair.alice.connect("Bob");
            pair.until(() -> pair.controls.size() == 2);
            var response = pair.controls.getLast();
            var field = DataTransferService.class.getDeclaredField("connections");
            field.setAccessible(true);
            Object connection = ((Map<?, ?>) field.get(pair.alice)).get("bob");
            var created = connection.getClass().getDeclaredField("created");
            created.setAccessible(true);
            created.setLong(connection, System.currentTimeMillis() - 60001);
            pair.alice.tick();
            assertTrue(first.ready().toCompletableFuture().isCompletedExceptionally());
            pair.alice.receive(response.routed("Bob", ControlPayload.Kind.EXCHANGE, -1));
            pair.alice.tick();
            pair.until(() -> !exchangeWorker(pair.alice).busy());
            assertTrue(new SessionService(root.resolve("alice-api")).find("Bob").isEmpty());
            pair.dropResponse = false;
            var second = pair.alice.connect("Bob");
            pair.until(second::isReady);
            assertEquals(new SessionService(root.resolve("bob-api")).find("Alice").orElseThrow().sessionId(),
                    new SessionService(root.resolve("alice-api")).find("Bob").orElseThrow().sessionId());
        }
    }
    @Test void failedResponseSendCanRetryTheSameAuthenticatedRequest() throws Exception {
        try (var pair = new Pair()) {
            pair.failResponse = true;
            pair.alice.connect("Bob");
            pair.until(() -> pair.responseFailures == 1);
            pair.until(() -> !exchangeWorker(pair.bob).busy());
            var request = pair.controls.getFirst();
            pair.failResponse = false;
            pair.bob.receive(request.routed("Alice", ControlPayload.Kind.EXCHANGE, -1));
            pair.bob.tick();
            pair.until(() -> !exchangeWorker(pair.bob).busy());
            assertTrue(new SessionService(root.resolve("bob-api")).find("Alice").isPresent(),
                    "Failed send must not burn the request's Message ID / Nonce");
        }
    }
    @Test void selfConnectionsAreRejectedBeforeExchange() throws Exception {
        try (var pair = new Pair()) {
            assertThrows(IllegalArgumentException.class, () -> pair.alice.connect("aLiCe"));
            assertThrows(IllegalArgumentException.class, () -> pair.alice.open("Alice", CHANNEL));
            pair.alice.tick();
            assertTrue(pair.controls.isEmpty());
        }
    }
    @Test void exchangeAllocationRawDuplexAndAuthenticatedEofWithoutReceipts() throws Exception {
        try (var pair = new Pair()) {
            var left = pair.alice.open("Bob", CHANNEL);
            byte[] bytes = new byte[33000]; new Random(7).nextBytes(bytes);
            left.getOutputStream().write(bytes); left.close();
            pair.until(() -> pair.right != null && pair.right.outputEnded() && left.isClosed());
            assertArrayEquals(bytes, pair.right.getInputStream().readAllBytes());
            assertArrayEquals(new byte[]{42}, left.getInputStream().readAllBytes());
            assertEquals(3, pair.raw.size());
            assertEquals(16384 + 16, pair.raw.getFirst().ciphertext().length);
            assertTrue(pair.controls.stream().allMatch(p -> Set.of(ControlPayload.Kind.EXCHANGE, ControlPayload.Kind.OPEN,
                    ControlPayload.Kind.ASSIGNED, ControlPayload.Kind.READY, ControlPayload.Kind.END).contains(p.kind())));
        }
    }
    @Test void droppedRecordFailsAtAuthenticatedEnd() throws Exception {
        try (var pair = new Pair()) {
            pair.dropData = true;
            var left = pair.alice.open("Bob", CHANNEL); left.getOutputStream().write(new byte[]{1}); left.close();
            pair.until(() -> pair.right != null && pair.right.isFailed());
            assertThrows(IOException.class, () -> pair.right.getInputStream().read());
            assertEquals(1, pair.raw.size()); // No retry or resend.
        }
    }
    @Test void replayAndCiphertextTamperingFailClosed() throws Exception {
        try (var pair = new Pair()) {
            pair.keepOpen = true;
            var left = pair.alice.open("Bob", CHANNEL); left.getOutputStream().write(new byte[]{1});
            pair.until(() -> pair.raw.size() == 1);
            pair.bob.receive(pair.raw.getFirst());
            assertTrue(pair.right.isFailed());
        }
        try (var pair = new Pair()) {
            pair.tamperData = true;
            var left = pair.alice.open("Bob", CHANNEL); left.getOutputStream().write(new byte[]{1});
            pair.until(() -> pair.right != null && pair.right.isFailed());
        }
    }
    @Test void forgedCloseCannotProduceEofAndDisconnectUnblocksReader() throws Exception {
        try (var pair = new Pair()) {
            pair.keepOpen = true;
            var left = pair.alice.open("Bob", CHANNEL);
            pair.until(() -> pair.right != null);
            var open = pair.controls.stream().filter(p -> p.kind() == ControlPayload.Kind.OPEN).findFirst().orElseThrow();
            var forged = new ControlPayload(ControlPayload.Kind.END, "Alice", open.id(), 0, CHANNEL,
                    open.sessionId(), 0, new byte[32]);
            pair.bob.receive(forged);
            assertFalse(pair.right.isClosed());
            pair.bob.clear();
            assertThrows(IOException.class, () -> pair.right.getInputStream().read());
            pair.alice.clear(); assertTrue(left.isFailed());
        }
    }
    @Test void disabledApiRejectsOpenButFileStreamUsesOwnSettings() throws Exception {
        try (var pair = new Pair()) {
            pair.config.enableDataApi = false;
            assertThrows(IllegalStateException.class, () -> pair.alice.open("Bob", CHANNEL));
            pair.config.enableFileSending = true;
            var socket = pair.alice.open("Bob", "krypt04mcg_file:stream");
            assertFalse(socket.isFailed());
        }
    }
    @Test void channelPoolAndStreamBuffersAreBounded() throws Exception {
        try (var pair = new Pair()) {
            for (int i = 0; i < pair.config.apiChannelCount; i++) pair.alice.open("Bob", CHANNEL);
            assertThrows(IllegalStateException.class, () -> pair.alice.open("Bob", CHANNEL));
        }
    }
    @Test void byteReceiverGetsStreamPortionsAndNoApplicationAcknowledgements() throws Exception {
        try (var pair = new Pair()) {
            Krypt04McgApi.unregisterSocketReceiver(CHANNEL);
            var received = new ByteArrayOutputStream();
            Krypt04McgApi.registerReceiver(CHANNEL, (peer, bytes) -> {
                assertEquals("Alice", peer); received.writeBytes(bytes);
            });
            byte[] bytes = new byte[33000]; Arrays.fill(bytes, (byte) 17);
            pair.alice.send("Bob", CHANNEL, bytes);
            pair.until(() -> received.size() == bytes.length);
            assertArrayEquals(bytes, received.toByteArray());
        }
    }
    @Test void pacedDataResumesAfterOutputBufferFills() throws Exception {
        try (var pair = new Pair()) {
            Krypt04McgApi.unregisterSocketReceiver(CHANNEL);
            var received = new ByteArrayOutputStream();
            Krypt04McgApi.registerReceiver(CHANNEL, (peer, bytes) -> received.writeBytes(bytes));
            var left = pair.alice.open("Bob", CHANNEL);
            byte[] bytes = new byte[2 * KryptSocket.MAX_BUFFERED_BYTES + 123];
            new Random(19).nextBytes(bytes);
            int offset = 0;
            while (offset < bytes.length) {
                int count = Math.min(left.writableBytes(), bytes.length - offset);
                if (count == 0) {
                    assertFalse(left.isFailed());
                    pair.until(() -> left.writableBytes() > 0 || left.isFailed());
                    assertFalse(left.isFailed());
                    continue;
                }
                left.getOutputStream().write(bytes, offset, count);
                offset += count;
                if (offset < bytes.length) assertEquals(0, left.writableBytes());
            }
            left.close();
            assertEquals(0, left.writableBytes());
            pair.until(left::isClosed);
            assertFalse(left.isFailed());
            assertArrayEquals(bytes, received.toByteArray());
        }
    }
    @Test void unsupportedServerLeavesTransportDormantAndFailsOnlyRequestedApiWork() throws Exception {
        try (var pair = new Pair()) {
            pair.unavailable = true;
            for (int i = 0; i < 50; i++) { pair.alice.tick(); pair.bob.tick(); }
            assertTrue(pair.controls.isEmpty()); assertTrue(pair.raw.isEmpty());
            assertThrows(IllegalStateException.class, () -> pair.alice.open("Bob", CHANNEL));
            assertThrows(IllegalStateException.class, () -> pair.alice.connect("Bob"));
        }
    }
    @Test void slotsCanBeReusedWithFreshKeysAndOldOpenCannotBeReplayed() throws Exception {
        try (var pair = new Pair()) {
            var first = pair.alice.open("Bob", CHANNEL); first.getOutputStream().write(1); first.close();
            pair.until(first::isClosed);
            var old = pair.raw.getFirst();
            var open = pair.controls.stream().filter(p -> p.kind() == ControlPayload.Kind.OPEN).findFirst().orElseThrow();
            pair.right = null;
            pair.bob.receive(open.routed("Alice", ControlPayload.Kind.OPEN, 0));
            assertNull(pair.right);
            pair.keepOpen = true;
            var next = pair.alice.open("Bob", CHANNEL);
            pair.until(() -> pair.right != null);
            pair.bob.receive(old);
            assertTrue(pair.right.isFailed());
            next.close();
        }
    }

    @Test void acceptedExchangeCannotResetSessionAfterDisconnect() throws Exception {
        try (var pair = new Pair()) {
            var connected = pair.alice.connect("Bob");
            pair.until(connected::isReady);
            var request = pair.controls.getFirst();
            var sessions = new SessionService(root.resolve("bob-api"));
            var original = sessions.find("Alice").orElseThrow();
            pair.alice.clear(); pair.bob.clear();
            pair.bob.receive(request.routed("Alice", ControlPayload.Kind.EXCHANGE, -1));
            pair.bob.tick();
            pair.until(() -> !exchangeWorker(pair.bob).busy());
            var restored = sessions.find("Alice").orElseThrow();
            assertEquals(original.sessionId(), restored.sessionId());
            assertTrue(original.secret().equals(new SessionService(root.resolve("alice-api"))
                    .find("Bob").orElseThrow().secret()), "The initiator must retain its established secret");
            assertTrue(original.secret().equals(restored.secret()), "Replay must not replace the responder's secret");
            assertTrue(original.equals(restored),
                    "Replaying a completed request must not replace its persisted session or counters");
            var freshStream = pair.alice.open("Bob", CHANNEL);
            pair.until(() -> pair.right != null);
            freshStream.close();
            pair.until(freshStream::isClosed);
        }
    }

    @Test void acceptedExchangeCannotResetSessionAfterServiceRestart() throws Exception {
        ControlPayload request;
        dev.krypt04mcg.model.SessionRecord original;
        try (var pair = new Pair()) {
            var connected = pair.alice.connect("Bob");
            pair.until(connected::isReady);
            request = pair.controls.getFirst();
            original = new SessionService(root.resolve("bob-api")).find("Alice").orElseThrow();
        }
        try (var restarted = new Pair()) {
            restarted.bob.receive(request.routed("Alice", ControlPayload.Kind.EXCHANGE, -1));
            restarted.bob.tick();
            restarted.until(() -> !exchangeWorker(restarted.bob).busy());
            var restored = new SessionService(root.resolve("bob-api")).find("Alice").orElseThrow();
            assertEquals(original.sessionId(), restored.sessionId());
            assertTrue(original.secret().equals(restored.secret()), "Restart must not permit session secret replacement");
            assertTrue(original.equals(restored),
                    "Accepted exchange history must survive a service restart");
        }
    }

    private static SharingWorker exchangeWorker(DataTransferService service) {
        try {
            var field = DataTransferService.class.getDeclaredField("worker");
            field.setAccessible(true);
            return (SharingWorker) field.get(service);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    @Test void acceptedOldExchangeCannotReplaceANewerSessionAfterRestart() throws Exception {
        ControlPayload request;
        String originalId;
        try (var pair = new Pair()) {
            var connected = pair.alice.connect("Bob");
            pair.until(connected::isReady);
            request = pair.controls.getFirst();
            originalId = new SessionService(root.resolve("bob-api")).find("Alice").orElseThrow().sessionId();
        }
        new SessionService(root.resolve("alice-api")).clear("Bob");
        new SessionService(root.resolve("bob-api")).clear("Alice");
        try (var restarted = new Pair()) {
            var connected = restarted.alice.connect("Bob");
            restarted.until(connected::isReady);
            var sessions = new SessionService(root.resolve("bob-api"));
            var current = sessions.find("Alice").orElseThrow();
            assertNotEquals(originalId, current.sessionId());
            restarted.bob.receive(request.routed("Alice", ControlPayload.Kind.EXCHANGE, -1));
            restarted.bob.tick();
            restarted.until(() -> !exchangeWorker(restarted.bob).busy());
            assertTrue(current.equals(sessions.find("Alice").orElseThrow()),
                    "A completed request must not roll back a newer session epoch");
        }
    }
    @Test void largeFileConsumesSocketAsStreamWithoutReassembly() throws Exception {
        try (var pair = new Pair(); var reader = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            pair.keepOpen = true;
            var left = pair.alice.open("Bob", CHANNEL);
            pair.until(() -> pair.right != null);
            byte[] bytes = new byte[2 * 1024 * 1024]; new Random(42).nextBytes(bytes);
            Path file = root.resolve("large-file.bin"); java.nio.file.Files.write(file, bytes);
            byte[] encoded = FileStreamCodec.encode(file);
            var incoming = pair.right;
            incoming.close();
            var received = reader.submit(() -> FileStreamCodec.read(incoming.getInputStream()));
            for (int offset = 0; offset < encoded.length;) {
                pair.until(() -> left.writableBytes() > 0 || left.isFailed());
                assertFalse(left.isFailed());
                int count = Math.min(left.writableBytes(), Math.min(64 * 1024, encoded.length - offset));
                left.getOutputStream().write(encoded, offset, count); offset += count;
                int expected = (offset + RawChannelPayload.MAX_PLAINTEXT - 1) / RawChannelPayload.MAX_PLAINTEXT;
                pair.until(() -> pair.raw.size() >= expected);
            }
            left.close(); pair.until(left::isClosed);
            var result = received.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals("large-file.bin", result.name()); assertArrayEquals(bytes, result.data());
        }
    }

    @Test void emptyAuthenticatedRecordCannotKeepIncompleteFileWorkerBusy() throws Exception {
        try (var pair = new Pair(); var worker = new SharingWorker()) {
            pair.keepOpen = true;
            var left = pair.alice.open("Bob", CHANNEL);
            pair.until(() -> pair.right != null);
            var incoming = pair.right;
            incoming.close();
            Path file = root.resolve("empty.bin");
            java.nio.file.Files.write(file, new byte[0]);
            left.getOutputStream().write(FileStreamCodec.encode(file));
            pair.until(() -> pair.raw.size() == 1);
            var completed = new java.util.concurrent.ConcurrentLinkedQueue<Runnable>();
            var failure = new java.util.concurrent.atomic.AtomicReference<Exception>();
            assertTrue(worker.submit(() -> FileStreamCodec.read(incoming.getInputStream()), completed::add,
                    (result, error) -> failure.set(error)));
            assertTrue(worker.busy());
            assertFalse(worker.submit(() -> null, completed::add, (result, error) -> {}));

            Object receiving = stream(pair.bob, left.streamId());
            var activity = receiving.getClass().getDeclaredField("lastActivity");
            activity.setAccessible(true);
            long expired = System.currentTimeMillis() - 60001;
            activity.setLong(receiving, expired);
            Object sending = stream(pair.alice, left.streamId());
            var crypto = sending.getClass().getDeclaredField("crypto");
            crypto.setAccessible(true);
            pair.bob.receive(new RawChannelPayload(0, ((ChannelCrypto) crypto.get(sending)).encrypt(new byte[0])));
            assertFalse(incoming.isFailed(), "Valid empty records remain protocol-compatible");
            assertEquals(expired, activity.getLong(receiving));
            pair.bob.tick();
            assertTrue(incoming.isFailed());
            pair.until(() -> !completed.isEmpty());
            completed.remove().run();
            assertInstanceOf(IOException.class, failure.get());
            assertFalse(worker.busy(), "Timeout must release the file reader's worker");
            assertTrue(worker.submit(() -> null, completed::add, (result, error) -> {}));
        }
    }

    @Test void nonemptyAuthenticatedRecordRefreshesStreamActivity() throws Exception {
        try (var pair = new Pair()) {
            pair.keepOpen = true;
            var left = pair.alice.open("Bob", CHANNEL);
            pair.until(() -> pair.right != null);
            Object receiving = stream(pair.bob, left.streamId());
            var activity = receiving.getClass().getDeclaredField("lastActivity");
            activity.setAccessible(true);
            activity.setLong(receiving, System.currentTimeMillis() - 60001);
            left.getOutputStream().write(7);
            pair.alice.tick();
            while (!pair.delivery.isEmpty()) pair.delivery.removeFirst().run();
            pair.bob.tick();
            assertFalse(pair.right.isFailed());
            assertEquals(7, pair.right.getInputStream().read());
        }
    }

    private static Object stream(DataTransferService service, UUID id) throws Exception {
        var streams = DataTransferService.class.getDeclaredField("streams");
        streams.setAccessible(true);
        return ((Map<?, ?>) streams.get(service)).get(id);
    }
    /** In-memory test fixture for the future plugin contract; no server code is shipped. */
    private static final class TestChannels {
        private final Route[] slots = new Route[2];
        private final java.util.function.BiConsumer<String, CustomPacketPayload> delivery;
        TestChannels(java.util.function.BiConsumer<String, CustomPacketPayload> delivery) { this.delivery = delivery; }
        void receive(String source, ControlPayload p) {
            if (p.kind() == ControlPayload.Kind.EXCHANGE) { delivery.accept(p.peer(), p.routed(source, p.kind(), -1)); return; }
            if (p.kind() == ControlPayload.Kind.OPEN) {
                for (int i = 0; i < slots.length; i++) if (slots[i] == null) {
                    slots[i] = new Route(source, p.peer());
                    delivery.accept(source, p.routed(p.peer(), ControlPayload.Kind.ASSIGNED, i));
                    delivery.accept(p.peer(), p.routed(source, ControlPayload.Kind.OPEN, i)); return;
                }
                delivery.accept(source, p.routed(p.peer(), ControlPayload.Kind.ABORT, -1)); return;
            }
            if (p.slot() < 0 || p.slot() >= slots.length || slots[p.slot()] == null) return;
            Route r = slots[p.slot()];
            if (p.kind() == ControlPayload.Kind.END) {
                if (source.equals(r.left)) r.leftEnded = true; else r.rightEnded = true;
            }
            delivery.accept(p.peer(), p.routed(source, p.kind(), p.slot()));
            if (p.kind() == ControlPayload.Kind.RESET || r.leftEnded && r.rightEnded) slots[p.slot()] = null;
        }
        void receive(String source, RawChannelPayload p) {
            Route r = slots[p.slot()];
            if (r != null) delivery.accept(source.equals(r.left) ? r.right : r.left, p);
        }
        private static final class Route {
            final String left, right; boolean leftEnded, rightEnded;
            Route(String left, String right) { this.left = left; this.right = right; }
        }
    }
    private final class Pair implements AutoCloseable {
        final Krypt04McgConfig config = new Krypt04McgConfig();
        final DataTransferService alice, bob;
        final SessionHandshakeService aliceHandshake, bobHandshake;
        final ArrayDeque<Runnable> delivery = new ArrayDeque<>();
        final List<RawChannelPayload> raw = new ArrayList<>();
        final List<ControlPayload> controls = new ArrayList<>();
        final TestChannels relay;
        KryptSocket right; boolean dropData, tamperData, keepOpen, unavailable, failResponse, dropResponse;
        int responseFailures;
        Pair() throws Exception {
            config.enableDataApi = true; config.apiChannelCount = 2;
            var crypto = new CryptoService();
            var a = new KeyStoreService(root.resolve("alice"), crypto);
            var b = new KeyStoreService(root.resolve("bob"), crypto);
            a.init("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
            b.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
            a.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(b.ownPublicIdentity()));
            b.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(a.ownPublicIdentity()));
            var as = new SessionService(root.resolve("alice-api")); var bs = new SessionService(root.resolve("bob-api"));
            aliceHandshake = new SessionHandshakeService(crypto, as); bobHandshake = new SessionHandshakeService(crypto, bs);
            relay = new TestChannels((peer, payload) -> delivery.addLast(() -> receive(peer, payload)));
            alice = new DataTransferService(config, a, new KeyTrustService(root.resolve("alice")), as, aliceHandshake,
                    () -> !unavailable, p -> send("Alice", p));
            bob = new DataTransferService(config, b, new KeyTrustService(root.resolve("bob")), bs, bobHandshake,
                    () -> !unavailable, p -> send("Bob", p));
            Krypt04McgApi.unregisterReceiver(CHANNEL);
            Krypt04McgApi.registerSocketReceiver(CHANNEL, socket -> {
                right = socket;
                if (!keepOpen) try { socket.getOutputStream().write(42); socket.close(); }
                catch (IOException e) { throw new UncheckedIOException(e); }
            });
        }
        void send(String source, CustomPacketPayload payload) {
            if (failResponse && source.equals("Bob") && payload instanceof ControlPayload p
                    && p.kind() == ControlPayload.Kind.EXCHANGE) {
                responseFailures++;
                throw new IllegalStateException("Simulated response send failure");
            }
            if (payload instanceof ControlPayload p) {
                controls.add(p);
                if (dropResponse && source.equals("Bob") && p.kind() == ControlPayload.Kind.EXCHANGE) return;
                relay.receive(source, p);
            }
            else if (payload instanceof RawChannelPayload p) {
                if (source.equals("Alice")) {
                    raw.add(p); if (dropData) return;
                    if (tamperData) { byte[] bytes = p.ciphertext().clone(); bytes[0] ^= 1; p = new RawChannelPayload(p.slot(), bytes); }
                }
                relay.receive(source, p);
            }
        }
        void receive(String peer, CustomPacketPayload p) {
            var target = peer.equalsIgnoreCase("Alice") ? alice : bob;
            if (p instanceof ControlPayload control) target.receive(control);
            else target.receive((RawChannelPayload) p);
        }
        void until(BooleanSupplier condition) throws Exception {
            long deadline = System.nanoTime() + 10_000_000_000L;
            while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
                alice.tick(); bob.tick();
                while (!delivery.isEmpty()) delivery.removeFirst().run();
                Thread.sleep(1);
            }
            assertTrue(condition.getAsBoolean(), "Transport did not reach expected state");
        }
        @Override public void close() {
            alice.close(); bob.close(); aliceHandshake.close(); bobHandshake.close();
            Krypt04McgApi.unregisterSocketReceiver(CHANNEL); Krypt04McgApi.unregisterReceiver(CHANNEL);
        }
    }
}
