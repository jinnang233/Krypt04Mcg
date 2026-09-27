package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.api.TransferResult.Status;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.protocol.DataTransferCodec.Kind;
import dev.krypt04mcg.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import static org.junit.jupiter.api.Assertions.*;

class DataTransferServiceTest {
    @TempDir Path root;
    private static final String CHANNEL = "service:test";

    @Test void queuesCopiesBytesAndAcknowledgesOnClientThread() throws Exception {
        try (var pair = new Pair()) {
            List<byte[]> delivered = new ArrayList<>();
            Thread client = Thread.currentThread();
            Krypt04McgApi.registerReceiver(CHANNEL, (sender, data) -> {
                assertEquals("Alice", sender);
                assertSame(client, Thread.currentThread());
                delivered.add(data);
            });
            byte[] bytes = {0, -1, -128, 42};
            var first = pair.alice.send(null, CHANNEL, bytes);
            bytes[0] = 99;
            var second = pair.alice.send(null, CHANNEL, new byte[0]);
            assertNotEquals(first.transferId(), second.transferId());
            assertFalse(done(first));
            var observed = new AtomicInteger();
            first.whenComplete(result -> {
                assertSame(client, Thread.currentThread());
                assertEquals(first.transferId(), result.transferId());
                observed.incrementAndGet();
            });
            pair.pumpUntil(() -> done(first) && done(second));
            assertEquals(Status.DELIVERED, status(first));
            assertEquals(Status.DELIVERED, status(second));
            assertEquals(1, observed.get());
            assertArrayEquals(new byte[]{0, -1, -128, 42}, delivered.get(0));
            assertArrayEquals(new byte[0], delivered.get(1));
        }
    }

    @Test void missingReceiverAndThrowingReceiverAreRejectedWithoutRepeatingCallback() throws Exception {
        try (var pair = new Pair()) {
            var missing = pair.alice.send(null, CHANNEL, new byte[0]);
            pair.pumpUntil(() -> done(missing));
            assertEquals(Status.REJECTED, status(missing));
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, data -> { calls.incrementAndGet(); throw new IllegalStateException("business failure"); });
            pair.dropBob = true;
            var failed = pair.alice.send(null, CHANNEL, new byte[0]);
            int oldReceipts = pair.bobSent.size();
            pair.pumpUntil(() -> pair.bobSent.size() > oldReceipts);
            pair.dropBob = false;
            pair.now.addAndGet(DataTransferService.ACK_TIMEOUT_MS + 1);
            pair.pumpUntil(() -> done(failed));
            assertEquals(Status.REJECTED, status(failed));
            assertEquals(1, calls.get());
        }
    }

    @Test void lostAckRetriesSameTransferWithoutDuplicateDelivery() throws Exception {
        try (var pair = new Pair()) {
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, data -> calls.incrementAndGet());
            pair.dropBob = true;
            var transfer = pair.alice.send(null, CHANNEL, new byte[]{1});
            pair.pumpUntil(() -> !pair.bobSent.isEmpty());
            assertEquals(1, calls.get());
            assertFalse(done(transfer));
            String original = assembled(pair.aliceSent);
            pair.aliceSent.clear();
            pair.dropBob = false;
            pair.now.addAndGet(DataTransferService.ACK_TIMEOUT_MS + 1);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.DELIVERED, status(transfer));
            assertEquals(original, assembled(pair.aliceSent));
            assertEquals(1, calls.get());
        }
    }

    @Test void lostFragmentRetriesAfterPartialAssemblyExpiresAndPacesPackets() throws Exception {
        try (var pair = new Pair()) {
            byte[] bytes = new byte[100000];
            new Random(42).nextBytes(bytes);
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, data -> { assertArrayEquals(bytes, data); calls.incrementAndGet(); });
            pair.dropFragment = 1;
            var transfer = pair.alice.send(null, CHANNEL, bytes);
            pair.pumpUntil(() -> pair.aliceSent.stream().anyMatch(DataTransferServiceTest::lastFragment));
            assertEquals(0, calls.get());
            pair.now.addAndGet(DataTransferService.ACK_TIMEOUT_MS + 1);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.DELIVERED, status(transfer));
            assertEquals(1, calls.get());
        }
    }

    @Test void retryBudgetAndQueueDeadlineAreBounded() throws Exception {
        try (var pair = new Pair()) {
            pair.dropAlice = true;
            var transfer = pair.alice.send(null, CHANNEL, new byte[0]);
            for (int attempt = 1; attempt <= DataTransferService.MAX_ATTEMPTS; attempt++) {
                int expected = attempt;
                pair.pumpUntil(() -> pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count() == expected);
                pair.now.addAndGet(DataTransferService.ACK_TIMEOUT_MS + 1);
            }
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.TIMEOUT, status(transfer));
            assertEquals(3, pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count());
            var queued = pair.alice.send(null, CHANNEL, new byte[0]);
            pair.now.addAndGet(DataTransferService.TRANSFER_TIMEOUT_MS);
            pair.pumpUntil(() -> done(queued));
            assertEquals(Status.TIMEOUT, status(queued));
        }
    }

    @Test void backpressureDisableDisconnectAndReentrantCompletionAreSafe() throws Exception {
        try (var pair = new Pair()) {
            pair.config.enableDataApi = false;
            assertEquals(Status.DISABLED, status(pair.alice.send(null, CHANNEL, new byte[0])));
            pair.config.enableDataApi = true;
            List<DataTransfer> queued = new ArrayList<>();
            for (int i = 0; i < DataTransferService.MAX_TRANSFERS; i++) queued.add(pair.alice.send(null, CHANNEL, new byte[0]));
            assertEquals(Status.BACKPRESSURE, status(pair.alice.send(null, CHANNEL, new byte[0])));
            AtomicReference<DataTransfer> reentrant = new AtomicReference<>();
            queued.get(0).whenComplete(result -> reentrant.set(pair.alice.send(null, CHANNEL, new byte[0])));
            pair.alice.clear();
            for (var transfer : queued) assertEquals(Status.DISCONNECTED, status(transfer));
            assertEquals(Status.DISCONNECTED, status(reentrant.get()));
            var large = pair.alice.send(null, CHANNEL, new byte[10 * 1024 * 1024]);
            assertEquals(Status.BACKPRESSURE, status(pair.alice.send(null, CHANNEL, new byte[10 * 1024 * 1024])));
            pair.alice.tick(); // Background encryption in flight when disabled.
            pair.config.enableDataApi = false;
            pair.alice.tick();
            assertEquals(Status.DISABLED, status(large));
            pair.config.enableDataApi = true;
            Krypt04McgApi.registerReceiver(CHANNEL, data -> assertEquals(1, data.length));
            var after = pair.alice.send(null, CHANNEL, new byte[]{1});
            pair.pumpUntil(() -> done(after));
            assertEquals(Status.DELIVERED, status(after));
        }
    }

    @Test void forgedWrongPeerWrongIdAndTamperedReceiptsCannotCompleteTransfer() throws Exception {
        try (var pair = new Pair()) {
            pair.dropAlice = true;
            var transfer = pair.alice.send(null, CHANNEL, new byte[0]);
            pair.pumpUntil(() -> !pair.aliceSent.isEmpty());
            var codec = new DataTransferCodec();
            String ownAck = codec.receipt(transfer.transferId(), Kind.ACK, pair.aliceKeys.ownPublicIdentity(),
                    pair.aliceKeys.local(), AeadAlgorithm.AES_256_GCM);
            pair.inject("Alice", ownAck);
            String wrongId = codec.receipt(UUID.randomUUID(), Kind.ACK, pair.aliceKeys.ownPublicIdentity(),
                    pair.bobKeys.local(), AeadAlgorithm.AES_256_GCM);
            pair.inject("Bob", wrongId);
            String ack = codec.receipt(transfer.transferId(), Kind.ACK, pair.aliceKeys.ownPublicIdentity(),
                    pair.bobKeys.local(), AeadAlgorithm.AES_256_GCM);
            var packet = codec.packet(ack, "Bob", pair.now.get());
            packet.signature()[0] ^= 1;
            pair.inject("Bob", Base64Url.encode(new PacketCodec(FileTransferCodec.MAX_ENVELOPE_BYTES + 65536).encode(packet)));
            for (int i = 0; i < 100; i++) { pair.tick(); Thread.sleep(2); }
            assertFalse(done(transfer));
            pair.inject("Bob", ack);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.DELIVERED, status(transfer));
        }
    }

    @Test void observerCannotCompleteTransportFutureAndLegacyMessagesStillDispatch() throws Exception {
        try (var pair = new Pair()) {
            pair.dropAlice = true;
            var transfer = pair.alice.send(null, CHANNEL, new byte[0]);
            var observer = transfer.completion().toCompletableFuture();
            observer.complete(new TransferResult(transfer.transferId(), Status.DELIVERED));
            assertFalse(done(transfer));
            pair.pumpUntil(() -> pair.aliceSent.stream().anyMatch(DataTransferServiceTest::lastFragment));
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, (sender, data) -> { assertEquals("Bob", sender); calls.incrementAndGet(); });
            var codec = new DataTransferCodec();
            String legacy = codec.encrypt(CHANNEL, new byte[0], pair.aliceKeys.ownPublicIdentity(), pair.bobKeys.local(), AeadAlgorithm.AES_256_GCM);
            pair.inject("Bob", legacy);
            pair.pumpUntil(() -> calls.get() == 1);
            int before = pair.aliceSent.size();
            for (int i = 0; i < 20; i++) { pair.tick(); Thread.sleep(2); }
            assertEquals(before, pair.aliceSent.size()); // Legacy data does not trigger a receipt.
        }
    }

    @Test void simultaneousLargeTransfersDoNotInterleaveReceiptsWithData() throws Exception {
        try (var pair = new Pair()) {
            byte[] bytes = new byte[200000];
            new Random(73).nextBytes(bytes);
            Set<String> delivered = new HashSet<>();
            Krypt04McgApi.registerReceiver(CHANNEL, (name, data) -> {
                assertArrayEquals(bytes, data);
                assertTrue(delivered.add(name));
            });
            var a = pair.alice.send("Bob", CHANNEL, bytes);
            var b = pair.bob.send("Alice", CHANNEL, bytes);
            pair.pumpUntil(() -> done(a) && done(b));
            assertEquals(Status.DELIVERED, status(a));
            assertEquals(Status.DELIVERED, status(b));
            assertEquals(Set.of("Alice", "Bob"), delivered);
        }
    }

    @Test void disconnectDiscardsBackgroundReceiveAndTrustIsRecheckedBeforeSend() throws Exception {
        try (var pair = new Pair()) {
            var calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, data -> calls.incrementAndGet());
            var codec = new DataTransferCodec();
            String data = codec.encrypt(UUID.randomUUID(), CHANNEL, new byte[0], pair.aliceKeys.ownPublicIdentity(),
                    pair.bobKeys.local(), AeadAlgorithm.AES_256_GCM);
            pair.inject("Bob", data);
            pair.alice.tick();
            pair.alice.clear();
            var pending = pair.alice.send(null, CHANNEL, new byte[0]);
            pair.aliceTrust.markDistrusted("Bob", pair.bobKeys.ownPublicIdentity());
            pair.pumpUntil(() -> done(pending));
            assertEquals(Status.FAILED, status(pending));
            assertEquals(0, calls.get());
            assertTrue(pair.aliceSent.isEmpty());
        }
    }

    private static boolean done(DataTransfer transfer) { return transfer.completion().toCompletableFuture().isDone(); }
    private static Status status(DataTransfer transfer) { return transfer.completion().toCompletableFuture().join().status(); }
    private static boolean lastFragment(DataPayload payload) {
        String[] fields = payload.fragment().split(":", 4);
        return Integer.parseInt(fields[1]) + 1 == Integer.parseInt(fields[2]);
    }
    private static String assembled(List<DataPayload> packets) {
        return packets.stream().map(p -> p.fragment().split(":", 4)[3]).reduce("", String::concat);
    }

    private final class Pair implements AutoCloseable {
        final AtomicLong now = new AtomicLong(System.currentTimeMillis());
        final Krypt04McgConfig config = new Krypt04McgConfig();
        final List<DataPayload> aliceSent = new ArrayList<>(), bobSent = new ArrayList<>();
        final KeyStoreService aliceKeys, bobKeys;
        final KeyTrustService aliceTrust;
        final DataTransferService alice, bob;
        boolean dropAlice, dropBob;
        int dropFragment = -1;
        Pair() throws Exception {
            Krypt04McgApi.unregisterReceiver(CHANNEL);
            var crypto = new CryptoService();
            aliceKeys = new KeyStoreService(root.resolve("alice"), crypto);
            bobKeys = new KeyStoreService(root.resolve("bob"), crypto);
            aliceKeys.init("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
            bobKeys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
            aliceKeys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(bobKeys.ownPublicIdentity()));
            bobKeys.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(aliceKeys.ownPublicIdentity()));
            config.apiReceiver = "Bob"; config.enableDataApi = true;
            aliceTrust = new KeyTrustService(root.resolve("alice"));
            alice = new DataTransferService(config, aliceKeys, aliceTrust, () -> true, this::fromAlice, now::get);
            bob = new DataTransferService(config, bobKeys, new KeyTrustService(root.resolve("bob")), () -> true, this::fromBob, now::get);
        }
        void fromAlice(DataPayload payload) {
            aliceSent.add(payload);
            if (dropAlice) return;
            if (Integer.parseInt(payload.fragment().split(":", 4)[1]) == dropFragment) { dropFragment = -1; return; }
            bob.receive(new DataPayload("alice", payload.fragment(), 1));
        }
        void fromBob(DataPayload payload) {
            bobSent.add(payload);
            if (!dropBob) alice.receive(new DataPayload("Bob", payload.fragment(), 1));
        }
        void inject(String sender, String envelope) {
            for (String fragment : OptionalTransferAssembler.split(envelope, FileTransferCodec.MAX_CHUNKS))
                alice.receive(new DataPayload(sender, fragment, 1));
        }
        void tick() {
            int a = aliceSent.size(), b = bobSent.size();
            alice.tick(); bob.tick();
            assertTrue(aliceSent.size() - a <= 4);
            assertTrue(bobSent.size() - b <= 4);
        }
        void pumpUntil(BooleanSupplier condition) throws Exception {
            long deadline = System.nanoTime() + 15_000_000_000L;
            while (!condition.getAsBoolean() && System.nanoTime() < deadline) { tick(); Thread.sleep(2); }
            assertTrue(condition.getAsBoolean(), "Transport did not reach expected state");
        }
        @Override public void close() { alice.close(); bob.close(); Krypt04McgApi.unregisterReceiver(CHANNEL); }
    }
}
