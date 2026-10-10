package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.*;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.*;
import dev.krypt04mcg.util.*;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class ChatSessionIdentityTest {
    @TempDir Path root;

    /**
     * Verifies that regenerated local keys reject old session receive without consuming state.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void regeneratedLocalKeysRejectOldSessionReceiveWithoutConsumingState() throws Exception {
        var f = fixture();
        var old = f.sessions.find("Alice").orElseThrow();
        f.keys.regenerate(f.keys.regenerationFingerprint(), KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        assertNotEquals(old.localFingerprint(), KeyTrustService.fingerprintPair(f.keys.ownPublicIdentity()));
        deliver(f, old, "old session secret");
        assertTrue(f.messages.isEmpty(), "A retired local identity must not authenticate new messages");
        assertEquals(old, f.sessions.find("Alice").orElseThrow());
    }

    /**
     * Verifies that regenerated local keys reject old session send without queuing ciphertext.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void regeneratedLocalKeysRejectOldSessionSendWithoutQueuingCiphertext() throws Exception {
        var f = fixture();
        var old = f.sessions.find("Alice").orElseThrow();
        f.keys.regenerate(f.keys.regenerationFingerprint(), KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        assertFalse(f.sender.sendSessionMessage("Alice", "new private message"));
        f.sender.tick();
        assertTrue(f.sent.isEmpty());
        assertTrue(f.cache.latest().isEmpty());
        assertEquals(old, f.sessions.find("Alice").orElseThrow());
    }

    /**
     * Verifies that sessions without local binding require a new handshake.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void sessionsWithoutLocalBindingRequireANewHandshake() throws Exception {
        var f = fixture();
        var legacy = f.sessions.find("Alice").orElseThrow().withLocalFingerprint("");
        f.sessions.save(legacy);
        deliver(f, legacy, "unbound session");
        assertTrue(f.messages.isEmpty());
        assertFalse(f.sender.sendSessionMessage("Alice", "unbound send"));
        assertEquals(legacy, f.sessions.find("Alice").orElseThrow());
    }

    /**
     * Verifies that current bound session still sends and receives.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void currentBoundSessionStillSendsAndReceives() throws Exception {
        var f = fixture();
        deliver(f, f.sessions.find("Alice").orElseThrow(), "current session");
        assertEquals(List.of("current session"), f.messages);
        assertTrue(f.sender.sendSessionMessage("Alice", "valid reply"));
        assertTrue(f.cache.latest().isPresent());
        assertEquals(1, f.sessions.find("Alice").orElseThrow().nextSendSequence());
        assertEquals(1, f.sessions.find("Alice").orElseThrow().nextReceiveSequence());
    }

    /**
     * Provides the deliver fixture operation used by the chat session identity test regression scenarios.
     *
     * @param f the f supplied to this operation
     * @param session the session supplied to this operation
     * @param message the message supplied to this operation
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private void deliver(Fixture f, SessionRecord session, String message) throws Exception {
        String json = JsonSupport.prettyGson().toJson(new SessionMessagePayload(SessionMessagePayload.VERSION, message));
        var packet = f.crypto.encryptWithSession("Bob", "Alice", Base64Url.decode(session.secret()),
                session.sessionId(), session.nextReceiveSequence(), json, false, AeadAlgorithm.AES_256_GCM);
        for (var fragment : f.fragments.fragment(f.codec.encode(packet), packet.messageId(), 96))
            f.receiver.handle(null, fragment);
    }

    /**
     * Provides the fixture fixture operation used by the chat session identity test regression scenarios.
     *
     * @return the result described above
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private Fixture fixture() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root.resolve("bob"), crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var alice = crypto.generateLocalKeys("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var aliceIdentity = new PublicIdentity("Alice", "alice", alice.kemPublicKey(), alice.signaturePublicKey());
        keys.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(aliceIdentity));
        var sessions = new SessionService(root.resolve("bob"));
        var trust = new KeyTrustService(root.resolve("bob"));
        var config = new Krypt04McgConfig();
        config.chatSendMode = ChatSendMode.CUSTOM_PAYLOAD;
        config.sendDelayMs = 0;
        var codec = new PacketCodec();
        var fragments = new FragmentService();
        var messages = new ArrayList<String>();
        var responses = new ArrayList<EncryptedPacket>();
        var bobHandshake = new SessionHandshakeService(crypto, sessions);
        var aliceHandshake = new SessionHandshakeService(crypto, new SessionService(root.resolve("alice")));
        try {
            var request = aliceHandshake.begin(keys.ownPublicIdentity(), alice, KemAlgorithm.ML_KEM_768, false,
                    AeadAlgorithm.AES_256_GCM);
            assertTrue(bobHandshake.complete(request, bobHandshake.decrypt(request, keys.local(), aliceIdentity),
                    aliceIdentity, keys.local(), false, AeadAlgorithm.AES_256_GCM, (p, peer) -> responses.add(p)));
            var response = responses.getFirst();
            assertTrue(aliceHandshake.complete(response, aliceHandshake.decrypt(response, alice, keys.ownPublicIdentity()),
                    keys.ownPublicIdentity(), alice, false, AeadAlgorithm.AES_256_GCM, (p, peer) -> fail("Unexpected response")));
        } finally {
            bobHandshake.close();
            aliceHandshake.close();
        }
        var history = new DecryptionHistoryService(root.resolve("bob"));
        var receiver = new ChatReceiveHandler(config, keys, trust, crypto, codec, fragments, new FragmentReassembler(),
                history, sessions, bobHandshake, (p, peer) -> {}, ignored -> {}, (peer, text) -> messages.add(text));
        var cache = new SentMessageCacheService(root.resolve("bob"));
        var sent = new ArrayList<ChatSendFragment>();
        Object connection = new Object();
        var sender = new ChatSendService(config, keys, trust, sessions, bobHandshake, cache, crypto, codec, fragments,
                sent::add, ignored -> {}, () -> connection);
        return new Fixture(crypto, keys, sessions, codec, fragments, receiver, sender, cache, messages, sent);
    }

    private record Fixture(CryptoService crypto, KeyStoreService keys, SessionService sessions, PacketCodec codec,
                           FragmentService fragments, ChatReceiveHandler receiver, ChatSendService sender,
                           SentMessageCacheService cache, List<String> messages, List<ChatSendFragment> sent) {}
}
