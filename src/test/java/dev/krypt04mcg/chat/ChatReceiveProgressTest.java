package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.*;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.*;
import dev.krypt04mcg.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.*;
import java.util.ArrayList;
import java.util.List;
import static dev.krypt04mcg.chat.TransferProgressTracker.*;
import static org.junit.jupiter.api.Assertions.*;

class ChatReceiveProgressTest {
    @TempDir Path root;
    private final Krypt04McgConfig config = new Krypt04McgConfig();
    private final FragmentService fragments = new FragmentService();
    private final List<Update> updates = new ArrayList<>();
    private final List<String> messages = new ArrayList<>();

    /**
     * Provides the bare receiver fixture operation used by the chat receive progress test regression
     * scenarios.
     *
     * @param reassembler the reassembler supplied to this operation
     * @return the result described above
     */
    private ChatReceiveHandler bareReceiver(FragmentReassembler reassembler) {
        var handler = new ChatReceiveHandler(config, null, null, null, new PacketCodec(), fragments,
                reassembler, null, null, null, (p, peer) -> {}, ignored -> {}, (peer, text) -> messages.add(text));
        handler.setProgressListener(updates::add);
        return handler;
    }

    /**
     * Provides the line fixture operation used by the chat receive progress test regression scenarios.
     *
     * @param message the message supplied to this operation
     * @param index the index supplied to this operation
     * @param total the total supplied to this operation
     * @param payload the payload supplied to this operation
     * @return the result described above
     */
    private String line(int message, int index, int total, String payload) {
        return FragmentService.PREFIX + " " + String.format("%032x", message) + " " + index + " " + total + " " + payload;
    }

    /**
     * Verifies that duplicates do not inflate progress and hex case does not split assemblies.
     */
    @Test void duplicatesDoNotInflateProgressAndHexCaseDoesNotSplitAssemblies() {
        var reassembler = new FragmentReassembler();
        var receiver = bareReceiver(reassembler);
        String first = line(0xab, 0, 3, "AQ");
        receiver.handle("Alice", first);
        receiver.handle("ALICE", first.replace("ab", "AB"));
        assertEquals(1, reassembler.pendingMessages());
        assertEquals(1, updates.getLast().completed());
        assertEquals(33, updates.getLast().percent());
        receiver.handle("Alice", line(0xab, 1, 3, "ID"));
        assertEquals(2, updates.getLast().completed());
        assertEquals(66, updates.getLast().percent());
    }

    /**
     * Verifies that forged incomplete message flood is bounded and other peer still gets progress.
     */
    @Test void forgedIncompleteMessageFloodIsBoundedAndOtherPeerStillGetsProgress() {
        var reassembler = new FragmentReassembler();
        var receiver = bareReceiver(reassembler);
        for (int i = 0; i < 128; i++) receiver.handle(i % 2 == 0 ? "Mallory" : "MALLORY", line(i, 0, 2, "AQ"));
        assertEquals(16, reassembler.pendingMessages());
        assertEquals(16, updates.size(), "Rejected IDs must not add HUD state");
        receiver.handle("Alice", line(999, 0, 2, "AQ"));
        assertEquals("Alice", updates.getLast().peer());
        assertEquals(17, reassembler.pendingMessages());
    }

    /**
     * Verifies that shadow chat uses one bounded unverified sender bucket.
     */
    @Test void shadowChatUsesOneBoundedUnverifiedSenderBucket() {
        var reassembler = new FragmentReassembler();
        var receiver = bareReceiver(reassembler);
        for (int i = 0; i < 128; i++) receiver.handle(null, line(i, 0, 2, "AQ"));
        assertEquals(16, reassembler.pendingMessages());
        assertEquals("unknown", updates.getLast().peer());
        receiver.handle("Alice", line(999, 0, 2, "AQ"));
        assertEquals("Alice", updates.getLast().peer());
    }

    /**
     * Verifies that malformed complete packet never reports verified completion.
     */
    @Test void malformedCompletePacketNeverReportsVerifiedCompletion() {
        var receiver = bareReceiver(new FragmentReassembler());
        receiver.handle("Alice", line(1, 0, 1, "AQID"));
        assertTrue(updates.stream().anyMatch(p -> p.status() == Status.VERIFYING));
        assertEquals(Status.FAILED, updates.getLast().status());
        assertTrue(updates.stream().noneMatch(p -> p.status() == Status.COMPLETE));
        assertTrue(messages.isEmpty());
    }

    /**
     * Verifies that conflicting total does not fail or overwrite admitted progress.
     */
    @Test void conflictingTotalDoesNotFailOrOverwriteAdmittedProgress() {
        var receiver = bareReceiver(new FragmentReassembler());
        receiver.handle("Alice", line(1, 0, 3, "AQ"));
        receiver.handle("Alice", line(1, 1, 2, "ID"));
        assertEquals(1, updates.getLast().completed());
        assertEquals(3, updates.getLast().total());
        assertEquals(Status.TRANSFERRING, updates.getLast().status());
    }

    /**
     * Verifies that idle tick expires receives without waiting for another message and attributes the
     * correct peer.
     */
    @Test void idleTickExpiresReceivesWithoutWaitingForAnotherMessageAndAttributesTheCorrectPeer() {
        var clock = new MutableClock();
        var reassembler = new FragmentReassembler(clock, Duration.ofSeconds(10), 128, 10);
        var receiver = bareReceiver(reassembler);
        receiver.handle("Alice", line(1, 0, 2, "AQ"));
        clock.now = clock.now.plusSeconds(5);
        receiver.handle("Bob", line(2, 0, 2, "AQ"));
        clock.now = clock.now.plusSeconds(5);
        receiver.tick();
        assertEquals(Status.TIMED_OUT, updates.getLast().status());
        assertEquals("alice", updates.getLast().peer());
        assertEquals(1, reassembler.pendingMessages());
    }

    /**
     * Verifies that clear pending prevents cross connection fragment splicing.
     */
    @Test void clearPendingPreventsCrossConnectionFragmentSplicing() {
        var reassembler = new FragmentReassembler();
        var receiver = bareReceiver(reassembler);
        receiver.handle("Alice", line(1, 0, 2, "AQ"));
        receiver.clearPending();
        receiver.handle("Alice", line(1, 1, 2, "ID"));
        assertEquals(Status.TRANSFERRING, updates.getLast().status());
        assertEquals(1, updates.getLast().completed());
        assertTrue(updates.stream().noneMatch(p -> p.status() == Status.COMPLETE || p.status() == Status.VERIFYING));
    }

    /**
     * Verifies that expiry inside admission also retires the previous progress row.
     */
    @Test void expiryInsideAdmissionAlsoRetiresThePreviousProgressRow() {
        var clock = new MutableClock();
        var reassembler = new FragmentReassembler(clock, Duration.ofSeconds(10), 128, 10);
        var receiver = bareReceiver(reassembler);
        receiver.handle("Alice", line(1, 0, 2, "AQ"));
        clock.now = clock.now.plusSeconds(10);
        reassembler.accept(new dev.krypt04mcg.model.Fragment("bob:new", 0, 2, "AQ"), "Bob");
        assertEquals(Status.TIMED_OUT, updates.getLast().status());
        assertEquals("alice", updates.getLast().peer());
    }

    /**
     * Verifies that verified message completes but replay fails without another plaintext delivery.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void verifiedMessageCompletesButReplayFailsWithoutAnotherPlaintextDelivery() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var alice = crypto.generateLocalKeys("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var aliceIdentity = new PublicIdentity("Alice", "alice", alice.kemPublicKey(), alice.signaturePublicKey());
        keys.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(aliceIdentity));
        var sessions = new SessionService(root);
        var handshake = new SessionHandshakeService(crypto, sessions);
        try {
            var codec = new PacketCodec();
            var receiver = new ChatReceiveHandler(config, keys, new KeyTrustService(root), crypto, codec,
                    fragments, new FragmentReassembler(), new DecryptionHistoryService(root), sessions, handshake,
                    (p, peer) -> {}, ignored -> {}, (peer, text) -> messages.add(text));
            receiver.setProgressListener(updates::add);
            var packet = crypto.encryptFor(keys.ownPublicIdentity(), alice, "Alice", "hello", true, false,
                    AeadAlgorithm.AES_256_GCM);
            var lines = fragments.fragment(codec.encode(packet), packet.messageId(), 180);
            for (String line : lines) receiver.handle("Alice", line);
            assertEquals(List.of("hello"), messages);
            assertEquals(Status.COMPLETE, updates.getLast().status());
            assertEquals(100, updates.getLast().percent());
            for (String line : lines) receiver.handle("Alice", line);
            assertEquals(Status.FAILED, updates.getLast().status());
            assertEquals(List.of("hello"), messages);
        } finally {
            handshake.close();
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.EPOCH;
        /**
         * Provides the get zone fixture operation used by the chat receive progress test regression scenarios.
         *
         * @return the result described above
         */
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        /**
         * Provides the with zone fixture operation used by the chat receive progress test regression
         * scenarios.
         *
         * @param zone the zone supplied to this operation
         * @return the result described above
         */
        @Override public Clock withZone(ZoneId zone) { return this; }
        /**
         * Provides the instant fixture operation used by the chat receive progress test regression scenarios.
         *
         * @return the result described above
         */
        @Override public Instant instant() { return now; }
    }
}
