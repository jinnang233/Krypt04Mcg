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
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

final class HandshakeFailureRecoveryTest {
    @TempDir Path root;

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

    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(),
                keys.kemPublicKey(), keys.signaturePublicKey());
    }
}
