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
                int count = Math.min(64 * 1024, encoded.length - offset);
                left.getOutputStream().write(encoded, offset, count); offset += count;
                int expected = (offset + RawChannelPayload.MAX_PLAINTEXT - 1) / RawChannelPayload.MAX_PLAINTEXT;
                pair.until(() -> pair.raw.size() >= expected);
            }
            left.close(); pair.until(left::isClosed);
            var result = received.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals("large-file.bin", result.name()); assertArrayEquals(bytes, result.data());
        }
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
        KryptSocket right; boolean dropData, tamperData, keepOpen, unavailable;
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
            if (payload instanceof ControlPayload p) { controls.add(p); relay.receive(source, p); }
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
