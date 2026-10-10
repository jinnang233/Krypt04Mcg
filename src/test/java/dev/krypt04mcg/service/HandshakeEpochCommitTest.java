package dev.krypt04mcg.service;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

final class HandshakeEpochCommitTest {
    @TempDir Path root;
    final CryptoService crypto = new CryptoService();
    static final AeadAlgorithm AEAD = AeadAlgorithm.AES_256_GCM;
    static final KemAlgorithm KEM = KemAlgorithm.ML_KEM_768;

    /**
     * Verifies that prepared responder can initiate recovery after peer installed candidate.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void preparedResponderCanInitiateRecoveryAfterPeerInstalledCandidate() throws Exception {
        try (var f = new Fixture()) {
            f.exchange();
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            assertThrows(SimulatedInterruption.class, () -> f.accept(request, (packet, peer) -> {
                responses.add(packet);
                throw new SimulatedInterruption();
            }));
            f.finish(responses.getFirst());
            f.restartResponder();
            var recovery = f.bh.begin(identity(f.alice), f.bob, KEM, false, AEAD);
            responses.clear();
            assertTrue(f.ah.complete(recovery, f.ah.decrypt(recovery, f.alice, identity(f.bob)), identity(f.bob),
                    f.alice, false, AEAD, (packet, peer) -> responses.add(packet)));
            var reply = responses.getFirst();
            assertTrue(f.bh.complete(reply, f.bh.decrypt(reply, f.bob, identity(f.alice)), identity(f.alice),
                    f.bob, false, AEAD, (packet, peer) -> fail()));
            f.assertAgreement();
        }
    }

    /**
     * Verifies that prepared responder can recover when peer restarted before receiving response.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void preparedResponderCanRecoverWhenPeerRestartedBeforeReceivingResponse() throws Exception {
        try (var f = new Fixture()) {
            f.exchange();
            var request = f.begin();
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> { throw new IOException("offline"); }));
            f.ah.close();
            f.as = new SessionService(root.resolve("alice"));
            f.ah = new SessionHandshakeService(crypto, f.as);
            f.restartResponder();
            boolean recovered = false;
            for (int attempt = 0; attempt < 2 && !recovered; attempt++) {
                var recovery = f.bh.begin(identity(f.alice), f.bob, KEM, false, AEAD);
                var replies = new ArrayList<EncryptedPacket>();
                try {
                    recovered = f.ah.complete(recovery, f.ah.decrypt(recovery, f.alice, identity(f.bob)), identity(f.bob),
                            f.alice, false, AEAD, (packet, peer) -> replies.add(packet));
                } catch (IOException candidateNotInstalled) {
                    f.bh.cancel("alice", dev.krypt04mcg.util.Hex.encode(recovery.messageId()));
                    continue;
                }
                var reply = replies.getFirst();
                assertTrue(f.bh.complete(reply, f.bh.decrypt(reply, f.bob, identity(f.alice)), identity(f.alice),
                        f.bob, false, AEAD, (packet, peer) -> fail()));
            }
            assertTrue(recovered, "Both possible peer states must permit a fresh handshake");
            f.assertAgreement();
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail()));
        }
    }

    /**
     * Verifies that recovery uses request predecessor after multiple lost responses.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void recoveryUsesRequestPredecessorAfterMultipleLostResponses() throws Exception {
        try (var f = new Fixture()) {
            f.exchange();
            f.accept(f.begin(), (packet, peer) -> {});
            // committed locally, never installed by the peer
            assertThrows(IOException.class, () -> f.accept(f.begin(), (packet, peer) -> { throw new IOException("offline"); }));
            f.ah.close();
            f.as = new SessionService(root.resolve("alice"));
            f.ah = new SessionHandshakeService(crypto, f.as);
            f.restartResponder();
            boolean recovered = false;
            for (int attempt = 0; attempt < 2 && !recovered; attempt++) {
                var recovery = f.bh.begin(identity(f.alice), f.bob, KEM, false, AEAD);
                var replies = new ArrayList<EncryptedPacket>();
                try {
                    recovered = f.ah.complete(recovery, f.ah.decrypt(recovery, f.alice, identity(f.bob)), identity(f.bob),
                            f.alice, false, AEAD, (packet, peer) -> replies.add(packet));
                } catch (IOException candidateNotInstalled) {
                    f.bh.cancel("alice", dev.krypt04mcg.util.Hex.encode(recovery.messageId()));
                    continue;
                }
                var reply = replies.getFirst();
                assertTrue(f.bh.complete(reply, f.bh.decrypt(reply, f.bob, identity(f.alice)), identity(f.alice),
                        f.bob, false, AEAD, (packet, peer) -> fail()));
            }
            assertTrue(recovered, "Recovery must cover the actual request predecessor, not only locally active keys");
            f.assertAgreement();
        }
    }

    /**
     * Verifies that error reported after atomic replacement still leaves one consistent epoch.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void errorReportedAfterAtomicReplacementStillLeavesOneConsistentEpoch() throws Exception {
        try (var f = new Fixture()) {
            f.exchange();
            var path = root.resolve("bob");
            var files = new SensitiveFileStore(path);
            var failAfterWrite = new AtomicBoolean(false);
            f.bh.close();
            f.bs = new SessionService(path, (destination, value) -> {
                files.writeDurableString(destination, value);
                if (failAfterWrite.get()) throw new IOException("Failure after atomic replacement");
            });
            f.bh = new SessionHandshakeService(crypto, f.bs);
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            try {
                assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> {
                    responses.add(packet);
                    failAfterWrite.set(true);
                }));
            } finally {
                failAfterWrite.set(false);
            }
            f.finish(responses.getFirst());
            f.assertAgreement();
            var committed = f.bs.find("alice").orElseThrow();
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail()));
            assertEquals(committed, f.bs.find("alice").orElseThrow());
        }
    }

    /**
     * Verifies that ephemeral key expiry rejects late response and allows fresh handshake.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void ephemeralKeyExpiryRejectsLateResponseAndAllowsFreshHandshake() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            f.accept(request, (packet, peer) -> responses.add(packet));
            // Age the pending record instead of sleeping for the five-minute TTL.
            var field = SessionHandshakeService.class.getDeclaredField("pending");
            field.setAccessible(true);
            @SuppressWarnings("unchecked")
            var pending = (java.util.Map<String, Object>) field.get(f.ah);
            var original = pending.get("bob");
            var components = original.getClass().getRecordComponents();
            var types = new Class<?>[components.length];
            var values = new Object[components.length];
            for (int i = 0; i < components.length; i++) {
                types[i] = components[i].getType();
                var accessor = components[i].getAccessor();
                accessor.setAccessible(true);
                values[i] = components[i].getName().equals("createdAt")
                        ? java.time.Instant.now().minusSeconds(301) : accessor.invoke(original);
            }
            var constructor = original.getClass().getDeclaredConstructor(types);
            constructor.setAccessible(true);
            pending.put("bob", constructor.newInstance(values));
            assertThrows(Exception.class, () -> f.finish(responses.getFirst()));
            assertTrue(pending.isEmpty());
            assertTrue(f.as.find("bob").isEmpty());
            f.exchange();
            f.assertAgreement();
        }
    }

    /**
     * Verifies that preparation failure does not send or consume replay state.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void preparationFailureDoesNotSendOrConsumeReplayState() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            f.failBobWrites.set(true);
            try {
                assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail("Prepare failed before send")));
                assertTrue(f.bs.find("alice").isEmpty());
            } finally {
                f.failBobWrites.set(false);
            }
            var responses = new ArrayList<EncryptedPacket>();
            assertTrue(f.accept(request, (packet, peer) -> responses.add(packet)));
            f.finish(responses.getFirst());
            f.assertAgreement();
        }
    }

    /**
     * Verifies that signed successor recovers an interrupted commit before rotating.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void signedSuccessorRecoversAnInterruptedCommitBeforeRotating() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            assertThrows(SimulatedInterruption.class, () -> f.accept(request, (packet, peer) -> {
                responses.add(packet);
                throw new SimulatedInterruption();
            }));
            f.finish(responses.getFirst());
            f.restartResponder();
            f.exchange();
            f.assertAgreement();
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail()));
        }
    }

    /**
     * Verifies that interrupted delivery reuses the persisted response after restart.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void interruptedDeliveryReusesThePersistedResponseAfterRestart() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            assertThrows(SimulatedInterruption.class, () -> f.accept(request, (packet, peer) -> {
                responses.add(packet);
                throw new SimulatedInterruption();
                // interruption after delivery, before commit
            }));
            f.finish(responses.getFirst());
            f.restartResponder();
            assertTrue(f.accept(request, (packet, peer) -> responses.add(packet)));
            assertArrayEquals(new PacketCodec().encode(responses.getFirst()), new PacketCodec().encode(responses.getLast()));
            f.assertAgreement();
            var established = f.bs.find("alice").orElseThrow();
            f.bs.recordSentMessage("alice", 0, 7);
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail()));
            assertEquals(established.secret(), f.bs.find("alice").orElseThrow().secret());
            assertEquals(1, f.bs.find("alice").orElseThrow().nextSendSequence());
        }
    }

    /**
     * Verifies that final commit failure is recoverable and never exposes old keys.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void finalCommitFailureIsRecoverableAndNeverExposesOldKeys() throws Exception {
        try (var f = new Fixture()) {
            f.exchange();
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            try {
                assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> {
                    responses.add(packet);
                    f.failBobWrites.set(true);
                }));
                assertThrows(IOException.class, () -> f.bs.find("alice"), "Uncertain switch must block predecessor keys");
                f.finish(responses.getFirst());
            } finally {
                f.failBobWrites.set(false);
            }
            f.restartResponder();
            assertTrue(f.accept(request, (packet, peer) -> responses.add(packet)));
            assertArrayEquals(new PacketCodec().encode(responses.getFirst()), new PacketCodec().encode(responses.getLast()));
            f.assertAgreement();
        }
    }

    /**
     * Verifies that initiator save failure retains the response key and allows retry.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void initiatorSaveFailureRetainsTheResponseKeyAndAllowsRetry() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            f.accept(request, (packet, peer) -> responses.add(packet));
            try {
                f.failAliceWrites.set(true);
                assertThrows(IOException.class, () -> f.finish(responses.getFirst()));
                assertTrue(f.as.find("bob").isEmpty());
            } finally {
                f.failAliceWrites.set(false);
            }
            f.finish(responses.getFirst());
            f.assertAgreement();
        }
    }

    /**
     * Verifies that lost response and initiator restart allow fresh negotiation.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void lostResponseAndInitiatorRestartAllowFreshNegotiation() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            f.accept(request, (packet, peer) -> {});
            // queue accepted, connection died before delivery
            var old = f.bs.find("alice").orElseThrow();
            f.ah.close();
            f.as = new SessionService(root.resolve("alice"));
            f.ah = new SessionHandshakeService(crypto, f.as);
            f.exchange();
            f.assertAgreement();
            assertNotEquals(old.sessionId(), f.bs.find("alice").orElseThrow().sessionId());
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail()));
        }
    }

    /**
     * Verifies that uncommitted response and initiator restart allow newer request.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void uncommittedResponseAndInitiatorRestartAllowNewerRequest() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> { throw new IOException("offline"); }));
            f.restartResponder();
            f.ah.close();
            f.ah = new SessionHandshakeService(crypto, new SessionService(root.resolve("alice")));
            f.exchange();
            f.assertAgreement();
            assertThrows(IOException.class, () -> f.accept(request, (packet, peer) -> fail()));
        }
    }

    /**
     * Verifies that stale responses cannot overwrite the winning request and rotation works both ways.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void staleResponsesCannotOverwriteTheWinningRequestAndRotationWorksBothWays() throws Exception {
        try (var f = new Fixture()) {
            var first = f.begin();
            var responses = new ArrayList<EncryptedPacket>();
            f.accept(first, (packet, peer) -> responses.add(packet));
            f.exchange();
            // supersedes the first pending request after a lost response
            assertThrows(Exception.class, () -> f.finish(responses.getFirst()));
            for (int i = 0; i < 3; i++) {
                var previous = f.as.find("bob").orElseThrow();
                var request = f.bh.begin(identity(f.alice), f.bob, KEM, false, AEAD);
                responses.clear();
                assertTrue(f.ah.complete(request, f.ah.decrypt(request, f.alice, identity(f.bob)), identity(f.bob),
                        f.alice, false, AEAD, (packet, peer) -> responses.add(packet)));
                var reply = responses.getFirst();
                assertTrue(f.bh.complete(reply, f.bh.decrypt(reply, f.bob, identity(f.alice)), identity(f.alice),
                        f.bob, false, AEAD, (packet, peer) -> fail()));
                f.assertAgreement();
                assertNotEquals(previous.secret(), f.as.find("bob").orElseThrow().secret());
                f.exchange();
                f.assertAgreement();
            }
        }
    }

    /**
     * Verifies that identity key rotation keeps the predecessor binding.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void identityKeyRotationKeepsThePredecessorBinding() throws Exception {
        try (var f = new Fixture()) {
            f.exchange();
            var old = f.begin();
            f.alice = crypto.generateLocalKeys("alice", "a", KEM, SignatureAlgorithm.ML_DSA_44);
            f.exchange();
            f.assertAgreement();
            assertEquals(KeyTrustService.fingerprintPair(identity(f.alice)), f.bs.find("alice").orElseThrow().peerFingerprint());
            assertThrows(Exception.class, () -> f.bh.decrypt(old, f.bob, identity(f.alice)));
        }
    }

    /**
     * Verifies that legacy payload cannot bypass epoch admission.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void legacyPayloadCannotBypassEpochAdmission() throws Exception {
        try (var f = new Fixture()) {
            var request = f.begin();
            var json = JsonSupport.prettyGson().fromJson(crypto.decrypt(request, f.bob, identity(f.alice)),
                    com.google.gson.JsonObject.class);
            json.addProperty("version", 1);
            json.remove("previousSessionId");
            json.remove("requestEpoch");
            var legacy = crypto.encryptSessionExchange(f.bob.kemPublicKey(), "bob", f.alice, "alice",
                    json.toString(), false, false, AEAD);
            assertThrows(IOException.class, () -> f.accept(legacy, (packet, peer) -> fail()));
            assertTrue(f.bs.find("alice").isEmpty());
            f.exchange();
            f.assertAgreement();
        }
    }

    private static final class SimulatedInterruption extends Error {}
    /**
     * Provides the identity fixture operation used by the handshake epoch commit test regression
     * scenarios.
     *
     * @param keys the keys supplied to this operation
     * @return the result described above
     */
    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(), keys.kemPublicKey(), keys.signaturePublicKey());
    }
    private final class Fixture implements AutoCloseable {
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "a", KEM, SignatureAlgorithm.ML_DSA_44);
        final LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "b", KEM, SignatureAlgorithm.ML_DSA_44);
        final AtomicBoolean failAliceWrites = new AtomicBoolean(), failBobWrites = new AtomicBoolean();
        SessionService as = faultStore("alice", failAliceWrites), bs = faultStore("bob", failBobWrites);
        SessionHandshakeService ah = new SessionHandshakeService(crypto, as), bh = new SessionHandshakeService(crypto, bs);
        /**
         * Creates the fixture fixture with its supplied initial state.
         *
         * @throws Exception if the delegated operation cannot complete successfully
         */
        Fixture() throws Exception {}
        /**
         * Provides the fault store fixture operation used by the handshake epoch commit test regression
         * scenarios.
         *
         * @param owner the owner identifier associated with the stored key records
         * @param failWrites the fail writes supplied to this operation
         * @return the result described above
         */
        SessionService faultStore(String owner, AtomicBoolean failWrites) {
            var path = root.resolve(owner);
            var files = new SensitiveFileStore(path);
            return new SessionService(path, (destination, value) -> {
                if (failWrites.get()) throw new IOException("Simulated ledger persistence failure");
                files.writeDurableString(destination, value);
            });
        }
        /**
         * Provides the begin fixture operation used by the handshake epoch commit test regression scenarios.
         *
         * @return the result described above
         * @throws Exception if the delegated operation cannot complete successfully
         */
        EncryptedPacket begin() throws Exception { return ah.begin(identity(bob), alice, KEM, false, AEAD); }
        /**
         * Provides the accept fixture operation used by the handshake epoch commit test regression scenarios.
         *
         * @param request the request supplied to this operation
         * @param sender the sender or source associated with this operation
         * @return whether the condition or operation described above succeeds
         * @throws Exception if the delegated operation cannot complete successfully
         */
        boolean accept(EncryptedPacket request, SessionHandshakeService.PacketSender sender) throws Exception {
            return bh.complete(request, bh.decrypt(request, bob, identity(alice)), identity(alice), bob, false, AEAD, sender);
        }
        /**
         * Provides the finish fixture operation used by the handshake epoch commit test regression scenarios.
         *
         * @param reply the reply supplied to this operation
         * @throws Exception if the delegated operation cannot complete successfully
         */
        void finish(EncryptedPacket reply) throws Exception {
            assertTrue(ah.complete(reply, ah.decrypt(reply, alice, identity(bob)), identity(bob), alice, false, AEAD, (p, peer) -> fail()));
        }
        /**
         * Provides the exchange fixture operation used by the handshake epoch commit test regression
         * scenarios.
         *
         * @throws Exception if the delegated operation cannot complete successfully
         */
        void exchange() throws Exception {
            var request = begin();
            var replies = new ArrayList<EncryptedPacket>();
            assertTrue(accept(request, (packet, peer) -> replies.add(packet)));
            finish(replies.getFirst());
        }
        /**
         * Provides the restart responder fixture operation used by the handshake epoch commit test regression
         * scenarios.
         */
        void restartResponder() { bh.close(); bs = new SessionService(root.resolve("bob")); bh = new SessionHandshakeService(crypto, bs); }
        /**
         * Provides the assert agreement fixture operation used by the handshake epoch commit test regression
         * scenarios.
         *
         * @throws Exception if the delegated operation cannot complete successfully
         */
        void assertAgreement() throws Exception {
            assertEquals(as.find("bob").orElseThrow().sessionId(), bs.find("alice").orElseThrow().sessionId());
            assertEquals(as.find("bob").orElseThrow().secret(), bs.find("alice").orElseThrow().secret());
        }
        /**
         * Provides the close fixture operation used by the handshake epoch commit test regression scenarios.
         */
        @Override public void close() { ah.close(); bh.close(); }
    }
}
