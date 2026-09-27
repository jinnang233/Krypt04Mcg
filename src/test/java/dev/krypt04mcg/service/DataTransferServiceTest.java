package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.api.TransferResult.Status;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.model.*;
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
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
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
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
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
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.DELIVERED, status(transfer));
            assertEquals(1, calls.get());
        }
    }

    @Test void customQueueLimitRetryCountAndAckDeadlineAreUsed() throws Exception {
        try (var pair = new Pair()) {
            pair.config.maxDataTransfers = 1;
            pair.config.maxDataAttempts = 1;
            pair.config.dataAckTimeoutSeconds = 70;
            pair.config.dataFragmentsPerTick = 1;
            pair.dropAlice = true;
            var transfer = pair.alice.send(null, CHANNEL, new byte[0]);
            assertEquals(Status.BACKPRESSURE, status(pair.alice.send(null, CHANNEL, new byte[0])));
            pair.pumpUntil(() -> pair.aliceSent.stream().anyMatch(DataTransferServiceTest::lastFragment));
            pair.now.addAndGet(69000);
            pair.tick();
            assertFalse(done(transfer));
            pair.now.addAndGet(1001);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.TIMEOUT, status(transfer));
            assertEquals(1, pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count());
        }
    }

    @Test void retryBudgetAndQueueDeadlineAreBounded() throws Exception {
        try (var pair = new Pair()) {
            pair.dropAlice = true;
            var transfer = pair.alice.send(null, CHANNEL, new byte[0]);
            for (int attempt = 1; attempt <= pair.config.maxDataAttempts(); attempt++) {
                int expected = attempt;
                pair.pumpUntil(() -> pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count() == expected);
                pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            }
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.TIMEOUT, status(transfer));
            assertEquals(3, pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count());
            var queued = pair.alice.send(null, CHANNEL, new byte[0]);
            pair.now.addAndGet(pair.config.dataTransferTimeoutSeconds() * 1000L);
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
            for (int i = 0; i < pair.config.maxDataTransfers(); i++) queued.add(pair.alice.send(null, CHANNEL, new byte[0]));
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

    @Test void boundedPipelineSendsPastWaitingHeadAndAcceptsDelayedOutOfOrderAcks() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            pair.config.dataTransferWindow = 4;
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            KryptSession session = pair.alice.connect("Bob");
            pair.dropBob = true;
            List<DataTransfer> transfers = new ArrayList<>();
            for (int i = 0; i < 6; i++) transfers.add(session.send(CHANNEL, new byte[] {(byte) i}));

            pair.pumpUntil(() -> pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count() >= 4
                    && pair.bobSent.stream().filter(DataTransferServiceTest::lastFragment).count() >= 4);
            long sentBeforeAck = pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count();
            for (int i = 0; i < 20; i++) { pair.tick(); Thread.sleep(2); }
            assertEquals(4, sentBeforeAck);
            assertEquals(4, pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count());
            assertTrue(transfers.stream().noneMatch(DataTransferServiceTest::done));

            List<List<DataPayload>> delayed = envelopes(pair.bobSent);
            pair.dropBob = false;
            Collections.reverse(delayed);
            for (List<DataPayload> envelope : delayed)
                for (DataPayload payload : envelope) pair.alice.receive(new DataPayload("Bob", payload.fragment(), 1));
            pair.pumpUntil(() -> transfers.stream().allMatch(DataTransferServiceTest::done));
            assertTrue(transfers.stream().allMatch(transfer -> status(transfer) == Status.DELIVERED));
            assertEquals(6, pair.aliceSent.stream().filter(DataTransferServiceTest::lastFragment).count());
        }
    }

    @Test void nackCompletesOnlyItsTransferWhileOtherPipelineEntriesSucceed() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            KryptSession session = pair.alice.connect("Bob");
            var first = session.send(CHANNEL, new byte[] {1});
            var rejected = session.send("missing:channel", new byte[] {2});
            var third = session.send(CHANNEL, new byte[] {3});
            pair.pumpUntil(() -> done(first) && done(rejected) && done(third));
            assertEquals(Status.DELIVERED, status(first));
            assertEquals(Status.REJECTED, status(rejected));
            assertEquals(Status.DELIVERED, status(third));
        }
    }

    @Test void lostEarlierTransferRetriesAfterLaterSequenceWithoutReplayFailure() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            pair.config.dataTransferWindow = 2;
            pair.dropNextAliceEnvelope = true;
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> calls.incrementAndGet());
            KryptSession session = pair.alice.connect("Bob");
            var first = session.send(CHANNEL, new byte[] {1});
            var second = session.send(CHANNEL, new byte[] {2});

            pair.pumpUntil(() -> done(second));
            assertEquals(Status.DELIVERED, status(second));
            assertFalse(done(first));
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            pair.pumpUntil(() -> done(first));
            assertEquals(Status.DELIVERED, status(first));
            assertEquals(2, calls.get());
        }
    }

    @Test void onePipelineTimeoutDoesNotRemoveCompletedNeighbor() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            pair.config.dataTransferWindow = 2;
            pair.config.maxDataAttempts = 1;
            pair.dropNextAliceEnvelope = true;
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            KryptSession session = pair.alice.connect("Bob");
            var lost = session.send(CHANNEL, new byte[] {1});
            var delivered = session.send(CHANNEL, new byte[] {2});

            pair.pumpUntil(() -> done(delivered));
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            pair.pumpUntil(() -> done(lost));
            assertEquals(Status.TIMEOUT, status(lost));
            assertEquals(Status.DELIVERED, status(delivered));
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

    @Test void connectQueuesUntilHandshakeAndSendsDomainSeparatedAead() throws Exception {
        try (var pair = new Pair()) {
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, (sender, bytes) -> { assertEquals("Alice", sender); calls.incrementAndGet(); });
            KryptSession session = pair.alice.connect("Bob");
            assertFalse(session.isReady());
            session.ready().toCompletableFuture().complete(session); // Observer cannot forge readiness.
            assertFalse(session.isReady());
            var first = session.send(CHANNEL, new byte[]{0, -1});
            var second = session.send(CHANNEL, new byte[0]);
            pair.pumpUntil(() -> done(first) && done(second));
            assertTrue(session.isReady());
            assertEquals(Status.DELIVERED, status(first));
            assertEquals(Status.DELIVERED, status(second));
            assertEquals(2, calls.get());
            SessionRecord remote = pair.bobSessions.find("Alice").orElseThrow();
            assertEquals(remote.sessionId(), session.sessionId());
            var dataPackets = packets(pair.aliceSent).stream().filter(p -> p.type() == PacketType.SESSION_MESSAGE).toList();
            assertEquals(2, dataPackets.size());
            assertEquals(0, dataPackets.get(0).sequence());
            assertEquals(2, dataPackets.get(1).sequence());
            for (var packet : dataPackets) {
                assertFalse(packet.signed());
                assertEquals(0, packet.kemCiphertext().length);
                assertEquals(session.sessionId(), packet.sessionId());
                assertThrows(CryptoException.class, () -> new CryptoService().decryptWithSession(packet, "Bob", "Alice",
                        Base64Url.decode(remote.secret()), remote.sessionId(), packet.sequence()));
            }
            assertEquals(0, remote.nextReceiveSequence()); // Chat sequence space remains untouched.
            assertEquals(2, remote.nextApiReceiveSequence());
        }
    }

    @Test void reusesChatExchangeAndClosingHandleDoesNotDeleteChatSession() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            String id = pair.aliceSessions.find("Bob").orElseThrow().sessionId();
            KryptSession session = pair.alice.connect("Bob");
            assertTrue(session.isReady());
            assertEquals(id, session.sessionId());
            assertSame(session, pair.alice.connect("bob"));
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            var transfer = session.send(CHANNEL, new byte[0]);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.DELIVERED, status(transfer));
            assertTrue(packets(pair.aliceSent).stream().allMatch(p -> p.type() == PacketType.SESSION_MESSAGE));
            var cancelled = session.send(CHANNEL, new byte[0]);
            session.close();
            assertFalse(session.isReady());
            assertEquals(Status.FAILED, status(cancelled));
            assertEquals(Status.FAILED, status(session.send(CHANNEL, new byte[0])));
            assertEquals(id, pair.aliceSessions.find("Bob").orElseThrow().sessionId());
            assertTrue(pair.alice.connect("Bob").isReady());
        }
    }

    @Test void sessionLostAckRetryReusesSequenceAndPersistedReplayProtection() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            var session = pair.alice.connect("Bob");
            AtomicInteger calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> calls.incrementAndGet());
            pair.dropBob = true;
            var transfer = session.send(CHANNEL, new byte[]{42});
            pair.pumpUntil(() -> !pair.bobSent.isEmpty());
            String original = assembled(pair.aliceSent);
            pair.aliceSent.clear();
            pair.dropBob = false;
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            pair.pumpUntil(() -> done(transfer));
            assertEquals(Status.DELIVERED, status(transfer));
            assertEquals(original, assembled(pair.aliceSent));
            assertEquals(1, calls.get());
            assertEquals(1, pair.aliceSessions.find("Bob").orElseThrow().nextApiSendSequence());
            assertEquals(1, new SessionService(root.resolve("bob")).find("Alice").orElseThrow().nextApiReceiveSequence());
            pair.bob.clear(); // Erases in-memory outcomes, not durable sequence state.
            int sent = pair.bobSent.size();
            for (String part : OptionalTransferAssembler.split(original, FileTransferCodec.MAX_CHUNKS))
                pair.bob.receive(new DataPayload("Alice", part, 1));
            pair.pumpUntil(() -> pair.bobSent.size() > sent);
            assertEquals(1, calls.get());
        }
    }

    @Test void simultaneousConnectionsConvergeOnOneEpoch() throws Exception {
        try (var pair = new Pair()) {
            var alice = pair.alice.connect("Bob");
            var bob = pair.bob.connect("Alice");
            var calls = new AtomicInteger();
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> calls.incrementAndGet());
            var a = alice.send(CHANNEL, new byte[]{1});
            var b = bob.send(CHANNEL, new byte[]{2});
            pair.pumpUntil(() -> done(a) && done(b));
            assertEquals(Status.DELIVERED, status(a));
            assertEquals(Status.DELIVERED, status(b));
            assertEquals(alice.sessionId(), bob.sessionId());
            assertEquals(2, calls.get());
        }
    }

    @Test void lostHandshakeResponseRetriesWithoutReplacingEstablishedSecret() throws Exception {
        try (var pair = new Pair()) {
            pair.dropBob = true;
            var session = pair.alice.connect("Bob");
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            var sent = session.send(CHANNEL, new byte[0]);
            pair.pumpUntil(() -> pair.bobSent.stream().filter(DataTransferServiceTest::lastFragment).count() >= 2);
            String secret = pair.bobSessions.find("Alice").orElseThrow().secret();
            assertFalse(session.isReady());
            pair.dropBob = false;
            pair.now.addAndGet(pair.config.dataAckTimeoutSeconds() * 1000L + 1);
            pair.pumpUntil(() -> done(sent));
            assertEquals(Status.DELIVERED, status(sent));
            assertEquals(secret, pair.aliceSessions.find("Bob").orElseThrow().secret());
            assertEquals(secret, pair.bobSessions.find("Alice").orElseThrow().secret());
        }
    }

    @Test void signedReceiptCannotAcknowledgeSessionTransfer() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            pair.dropAlice = true;
            var session = pair.alice.connect("Bob");
            var sent = session.send(CHANNEL, new byte[0]);
            pair.pumpUntil(() -> !pair.aliceSent.isEmpty());
            var codec = new DataTransferCodec();
            pair.inject("Bob", codec.receipt(sent.transferId(), Kind.ACK, pair.aliceKeys.ownPublicIdentity(), pair.bobKeys.local(), AeadAlgorithm.AES_256_GCM));
            for (int i = 0; i < 100; i++) { pair.tick(); Thread.sleep(2); }
            assertFalse(done(sent));
            var remote = pair.bobSessions.find("Alice").orElseThrow();
            long sequence = pair.bobSessions.reserveApiSend("Alice", remote.sessionId(), true, 0);
            pair.inject("Bob", codec.encryptSession(sent.transferId(), null, null, Kind.ACK, pair.aliceKeys.ownPublicIdentity(),
                    pair.bobKeys.local(), remote, sequence, AeadAlgorithm.AES_256_GCM));
            pair.pumpUntil(() -> done(sent));
            assertEquals(Status.DELIVERED, status(sent));
        }
    }

    @Test void apiUsesIndependentRotationBudgetAndReconnectsAfterItsOwnLimit() throws Exception {
        try (var pair = new Pair()) {
            pair.exchange();
            pair.config.maxMessagesPerSession = 1;
            pair.config.rotateAfterBytes = 1;
            pair.config.apiMaxMessagesPerSession = 2;
            pair.config.apiRotateAfterBytes = 1024;
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            var old = pair.alice.connect("Bob");
            String id = old.sessionId();
            var one = old.send(CHANNEL, new byte[10]);
            pair.pumpUntil(() -> done(one));
            assertEquals(Status.DELIVERED, status(one));
            var two = old.send(CHANNEL, new byte[10]);
            pair.pumpUntil(() -> done(two));
            assertEquals(Status.DELIVERED, status(two)); // Ordinary 1-message/1-byte budget did not stop API data.
            assertEquals(id, old.sessionId());
            var exhausted = old.send(CHANNEL, new byte[10]);
            pair.pumpUntil(() -> done(exhausted));
            assertEquals(Status.FAILED, status(exhausted));
            var fresh = pair.alice.connect("Bob");
            assertFalse(old.isReady());
            var afterRotation = fresh.send(CHANNEL, new byte[10]);
            pair.pumpUntil(() -> done(afterRotation));
            assertEquals(Status.DELIVERED, status(afterRotation));
            assertNotEquals(id, fresh.sessionId());
        }
    }

    @Test void disconnectInvalidatesConnectingHandleAndItsBoundedQueuedSends() throws Exception {
        try (var pair = new Pair()) {
            var connection = pair.alice.connect("Bob");
            List<DataTransfer> queued = new ArrayList<>();
            for (int i = 0; i < pair.config.maxDataTransfers() - 1; i++) queued.add(connection.send(CHANNEL, new byte[0]));
            assertEquals(Status.BACKPRESSURE, status(connection.send(CHANNEL, new byte[0])));
            pair.alice.tick();
            pair.alice.clear();
            assertTrue(connection.ready().toCompletableFuture().isCompletedExceptionally());
            assertFalse(connection.isReady());
            for (var send : queued) assertEquals(Status.DISCONNECTED, status(send));
            Krypt04McgApi.registerReceiver(CHANNEL, bytes -> {});
            var next = pair.alice.connect("Bob");
            var sent = next.send(CHANNEL, new byte[0]);
            pair.pumpUntil(() -> done(sent));
            assertEquals(Status.DELIVERED, status(sent));
            assertEquals(Status.FAILED, status(connection.send(CHANNEL, new byte[0])));
        }
    }

    private static List<EncryptedPacket> packets(List<DataPayload> payloads) {
        Map<String, StringBuilder> encoded = new LinkedHashMap<>();
        for (DataPayload payload : payloads) {
            String[] fields = payload.fragment().split(":", 4);
            encoded.computeIfAbsent(fields[0], ignored -> new StringBuilder()).append(fields[3]);
        }
        var codec = new PacketCodec(FileTransferCodec.MAX_ENVELOPE_BYTES + 65536);
        return encoded.values().stream().map(value -> codec.decode(Base64Url.decode(value.toString()))).toList();
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

    private static List<List<DataPayload>> envelopes(List<DataPayload> payloads) {
        Map<String, List<DataPayload>> grouped = new LinkedHashMap<>();
        for (DataPayload payload : payloads)
            grouped.computeIfAbsent(payload.fragment().split(":", 2)[0], ignored -> new ArrayList<>()).add(payload);
        return new ArrayList<>(grouped.values());
    }

    private final class Pair implements AutoCloseable {
        final AtomicLong now = new AtomicLong(System.currentTimeMillis());
        final Krypt04McgConfig config = new Krypt04McgConfig();
        final List<DataPayload> aliceSent = new ArrayList<>(), bobSent = new ArrayList<>();
        final KeyStoreService aliceKeys, bobKeys;
        final KeyTrustService aliceTrust;
        final SessionService aliceSessions, bobSessions;
        final SessionHandshakeService aliceHandshake, bobHandshake;
        final DataTransferService alice, bob;
        boolean dropAlice, dropBob;
        boolean dropNextAliceEnvelope;
        String droppedAliceEnvelope;
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
            aliceSessions = new SessionService(root.resolve("alice"));
            bobSessions = new SessionService(root.resolve("bob"));
            aliceHandshake = new SessionHandshakeService(crypto, aliceSessions);
            bobHandshake = new SessionHandshakeService(crypto, bobSessions);
            alice = new DataTransferService(config, aliceKeys, aliceTrust, aliceSessions, aliceHandshake, () -> true, this::fromAlice, now::get);
            bob = new DataTransferService(config, bobKeys, new KeyTrustService(root.resolve("bob")), bobSessions, bobHandshake, () -> true, this::fromBob, now::get);
        }
        void exchange() throws Exception {
            var request = aliceHandshake.begin(bobKeys.ownPublicIdentity(), aliceKeys.local(), KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            var response = new AtomicReference<EncryptedPacket>();
            bobHandshake.complete(request, bobHandshake.decrypt(request, bobKeys.local(), aliceKeys.ownPublicIdentity()), aliceKeys.ownPublicIdentity(),
                    bobKeys.local(), false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> response.set(packet));
            aliceHandshake.complete(response.get(), aliceHandshake.decrypt(response.get(), aliceKeys.local(), bobKeys.ownPublicIdentity()),
                    bobKeys.ownPublicIdentity(), aliceKeys.local(), false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> fail("Unexpected response"));
        }
        void fromAlice(DataPayload payload) {
            aliceSent.add(payload);
            if (dropAlice) return;
            String envelope = payload.fragment().split(":", 2)[0];
            if (dropNextAliceEnvelope && droppedAliceEnvelope == null) droppedAliceEnvelope = envelope;
            if (envelope.equals(droppedAliceEnvelope)) return;
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
            assertTrue(aliceSent.size() - a <= config.dataFragmentsPerTick());
            assertTrue(bobSent.size() - b <= config.dataFragmentsPerTick());
        }
        void pumpUntil(BooleanSupplier condition) throws Exception {
            long deadline = System.nanoTime() + 15_000_000_000L;
            while (!condition.getAsBoolean() && System.nanoTime() < deadline) { tick(); Thread.sleep(2); }
            assertTrue(condition.getAsBoolean(), "Transport did not reach expected state");
        }
        @Override public void close() { alice.close(); bob.close(); aliceHandshake.close(); bobHandshake.close(); Krypt04McgApi.unregisterReceiver(CHANNEL); }
    }
}
