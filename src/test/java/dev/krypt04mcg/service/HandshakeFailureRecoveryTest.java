package dev.krypt04mcg.service;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

final class HandshakeFailureRecoveryTest {
    @TempDir Path root;

    /**
     * Verifies that unseen older request cannot replace newer epoch after restart.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void unseenOlderRequestCannotReplaceNewerEpochAfterRestart() throws Exception {
        var crypto = new CryptoService();
        var alice = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("bob", "b", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var sessions = new SessionService(root.resolve("bob"));
        try (var initiator = new SessionHandshakeService(crypto, new SessionService(root.resolve("alice")));
             var responder = new SessionHandshakeService(crypto, sessions)) {
            var old = initiator.begin(identity(bob), alice, KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            var current = initiator.begin(identity(bob), alice, KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            responder.complete(current, responder.decrypt(current, bob, identity(alice)), identity(alice), bob,
                    false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> {});
            var established = sessions.find("alice").orElseThrow();
            try (var restarted = new SessionHandshakeService(crypto, new SessionService(root.resolve("bob")))) {
                var decrypted = restarted.decrypt(old, bob, identity(alice));
                assertThrows(IOException.class, () -> restarted.complete(old, decrypted, identity(alice), bob,
                        false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> fail("Stale request must not send")));
            }
            assertEquals(established, sessions.find("alice").orElseThrow());
        }
    }

    /**
     * Verifies that persistence failure must not expose an unrecoverable response.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void persistenceFailureMustNotExposeAnUnrecoverableResponse() throws Exception {
        var crypto = new CryptoService();
        var alice = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("bob", "b", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var store = root.resolve("bob");
        try (var initiator = new SessionHandshakeService(crypto, new SessionService(root.resolve("alice")));
             var responder = new SessionHandshakeService(crypto, new SessionService(store))) {
            var request = initiator.begin(identity(bob), alice, KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            var decrypted = responder.decrypt(request, bob, identity(alice));
            java.nio.file.Files.createDirectories(store);
            java.nio.file.Files.writeString(store.resolve("sessions"), "blocked");
            var responses = new ArrayList<EncryptedPacket>();
            assertThrows(IOException.class, () -> responder.complete(request, decrypted, identity(alice), bob,
                    false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> responses.add(packet)));
            assertTrue(responses.isEmpty(), "Response must have a durable recovery record before delivery");
            java.nio.file.Files.delete(store.resolve("sessions"));
            assertTrue(responder.complete(request, decrypted, identity(alice), bob, false,
                    AeadAlgorithm.AES_256_GCM, (packet, peer) -> responses.add(packet)));
            var reply = responses.getFirst();
            initiator.complete(reply, initiator.decrypt(reply, alice, identity(bob)), identity(bob), alice,
                    false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> fail());
        }
    }

    /**
     * Verifies that established epoch rejects replay even without recorded exchange history.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void establishedEpochRejectsReplayEvenWithoutRecordedExchangeHistory() throws Exception {
        var crypto = new CryptoService();
        var alice = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("bob", "b", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var sessions = new SessionService(root.resolve("bob"));
        try (var initiator = new SessionHandshakeService(crypto, new SessionService(root.resolve("alice")));
             var responder = new SessionHandshakeService(crypto, sessions)) {
            var request = initiator.begin(identity(bob), alice, KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            assertTrue(responder.complete(request, responder.decrypt(request, bob, identity(alice)), identity(alice),
                    bob, false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> {}));
            sessions.recordSentMessage("alice", 0, 4);
            var established = sessions.find("alice").orElseThrow();
            // Represents an established session saved before durable API replay tracking existed.
            try (var restarted = new SessionHandshakeService(crypto, new SessionService(root.resolve("bob")))) {
                var decrypted = restarted.decrypt(request, bob, identity(alice));
                assertThrows(IOException.class, () -> restarted.complete(request, decrypted, identity(alice), bob,
                        false, AeadAlgorithm.AES_256_GCM, (packet, peer) -> fail("A replay must not send a response")));
            }
            assertTrue(established.equals(sessions.find("alice").orElseThrow()));
        }
    }

    /**
     * Verifies that failed simultaneous request preserves pending response key.
     *
     * @param invalidKey the invalid key supplied to this operation
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void failedSimultaneousRequestPreservesPendingResponseKey(boolean invalidKey) throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "b", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        SessionService aliceSessions = new SessionService(root.resolve("alice"));
        SessionService bobSessions = new SessionService(root.resolve("bob"));
        try (var initiator = new SessionHandshakeService(crypto, bobSessions);
             var competing = new SessionHandshakeService(crypto, aliceSessions);
             var responder = new SessionHandshakeService(crypto, aliceSessions)) {
            EncryptedPacket bobRequest = initiator.begin(identity(alice), bob, KemAlgorithm.ML_KEM_768,
                    false, AeadAlgorithm.AES_256_GCM);
            EncryptedPacket aliceRequest = competing.begin(identity(bob), alice, KemAlgorithm.ML_KEM_768,
                    false, AeadAlgorithm.AES_256_GCM);
            if (invalidKey) {
                var payload = JsonSupport.prettyGson().fromJson(crypto.decrypt(aliceRequest, bob, identity(alice)),
                        com.google.gson.JsonObject.class);
                payload.addProperty("ephemeralPublicKey", "AA");
                aliceRequest = crypto.encryptSessionExchange(bob.kemPublicKey(), "bob", alice, "alice",
                        payload.toString(), false, false, AeadAlgorithm.AES_256_GCM);
            }
            EncryptedPacket incoming = aliceRequest;
            var decrypted = initiator.decrypt(incoming, bob, identity(alice));
            assertThrows(Exception.class, () -> initiator.complete(incoming, decrypted, identity(alice), bob,
                    false, AeadAlgorithm.AES_256_GCM, (packet, receiver) -> {
                        if (invalidKey) fail("Invalid ephemeral key must not be sent");
                        throw new IOException("Simulated send queue failure");
                    }));
            assertTrue(bobSessions.find("alice").isEmpty());

            var requestAtAlice = responder.decrypt(bobRequest, alice, identity(bob));
            ArrayList<EncryptedPacket> replies = new ArrayList<>();
            responder.complete(bobRequest, requestAtAlice, identity(bob), alice, false,
                    AeadAlgorithm.AES_256_GCM, (packet, receiver) -> replies.add(packet));
            EncryptedPacket reply = replies.getFirst();
            var replyAtBob = initiator.decrypt(reply, bob, identity(alice));
            assertTrue(initiator.complete(reply, replyAtBob, identity(alice), bob, false,
                    AeadAlgorithm.AES_256_GCM, (packet, receiver) -> fail("Response must not send")));
            assertEquals(aliceSessions.find("bob").orElseThrow().secret(), bobSessions.find("alice").orElseThrow().secret());
        }
    }

    /**
     * Provides the identity fixture operation used by the handshake failure recovery test regression
     * scenarios.
     *
     * @param keys the keys supplied to this operation
     * @return the result described above
     */
    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(),
                keys.kemPublicKey(), keys.signaturePublicKey());
    }
}
