package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.ChatSendFragment;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.service.*;
import dev.krypt04mcg.util.JsonSupport;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class ChatResendTrustTest {
    @TempDir Path root;

    /**
     * Verifies that large default chat selects available payload and fails early without it.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void largeDefaultChatSelectsAvailablePayloadAndFailsEarlyWithoutIt() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(keys.ownPublicIdentity()));
        var config = new Krypt04McgConfig();
        config.enableCompression = false;
        var chat = new ArrayList<ChatSendFragment>();
        var payload = new ArrayList<ChatSendFragment>();
        var errors = new ArrayList<String>();
        Object connection = new Object();
        var service = new ChatSendService(config, keys, new KeyTrustService(root), null, null,
                new SentMessageCacheService(root), crypto, new dev.krypt04mcg.protocol.PacketCodec(),
                new dev.krypt04mcg.fragment.FragmentService(), chat::add, errors::add, () -> connection);
        service.setCustomPayloadTransport(payload::add, () -> true);
        assertTrue(service.sendKemMessage("Bob", "x".repeat(65536), true));
        service.tick();
        assertEquals(1, payload.size());
        assertTrue(chat.isEmpty());
        service.setCustomPayloadTransport(payload::add, () -> false);
        int noticesBeforeFailure = errors.size();
        assertFalse(service.sendKemMessage("Bob", "x".repeat(65536), true));
        service.tick();
        assertEquals(1, payload.size());
        assertTrue(chat.isEmpty());
        assertTrue(errors.size() > noticesBeforeFailure);
    }

    /**
     * Verifies that new ciphertext persists recipient binding and can be resent.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void newCiphertextPersistsRecipientBindingAndCanBeResent() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var identity = keys.ownPublicIdentity();
        keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(identity));
        var cache = new SentMessageCacheService(root);
        var config = new Krypt04McgConfig();
        config.chatSendMode = ChatSendMode.CUSTOM_PAYLOAD;
        config.sendDelayMs = 0;
        var sent = new ArrayList<ChatSendFragment>();
        Object connection = new Object();
        var service = new ChatSendService(config, keys, new KeyTrustService(root), null, null, cache,
                crypto, new dev.krypt04mcg.protocol.PacketCodec(), new dev.krypt04mcg.fragment.FragmentService(),
                sent::add, ignored -> {}, () -> connection);
        assertTrue(service.sendKemMessage("Bob", "dummy secret", true));
        var cached = cache.latest().orElseThrow();
        assertEquals(KeyTrustService.fingerprintPair(identity), cached.recipientFingerprint());
        for (int i = 0; i < cached.fragments().size(); i++) service.tick();
        assertEquals(cached.fragments(), sent.stream().map(ChatSendFragment::fragment).toList());
        sent.clear();
        service.resend(cached.messageId());
        for (int i = 0; i < cached.fragments().size(); i++) service.tick();
        assertEquals(cached.fragments(), sent.stream().map(ChatSendFragment::fragment).toList());
    }

    /**
     * Verifies that cached resend rechecks current trust.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void cachedResendRechecksCurrentTrust() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var identity = keys.ownPublicIdentity();
        keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(identity));
        var trust = new KeyTrustService(root);
        var cache = new SentMessageCacheService(root);
        cache.remember("cached", "Bob", List.of("encrypted-fragment"), KeyTrustService.fingerprintPair(identity));
        var sent = new ArrayList<ChatSendFragment>();
        var config = new Krypt04McgConfig();
        config.chatSendMode = ChatSendMode.CUSTOM_PAYLOAD;
        config.sendDelayMs = 0;
        Object connection = new Object();
        var service = new ChatSendService(config, keys, trust, null, null, cache,
                crypto, null, null, sent::add, ignored -> {}, () -> connection);

        service.resendLatest();
        service.tick();
        assertEquals(1, sent.size());
        trust.markDistrusted("Bob", identity);
        service.resendLatest();
        service.resend("cached");
        service.tick();
        assertEquals(1, sent.size(), "Distrusted cached recipients must not be queued");
    }

    /**
     * Verifies that pending fragments recheck revocation deletion and replacement.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void pendingFragmentsRecheckRevocationDeletionAndReplacement() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var identity = new PublicIdentity("Bob", "bob", bob.kemPublicKey(), bob.signaturePublicKey());
        String original = JsonSupport.prettyGson().toJson(identity);
        keys.importPublicIdentity("Bob", original);
        var trust = new KeyTrustService(root);
        var cache = new SentMessageCacheService(root);
        cache.remember("cached", "Bob", List.of("first", "remaining"), KeyTrustService.fingerprintPair(identity));
        var sent = new ArrayList<ChatSendFragment>();
        var config = new Krypt04McgConfig();
        config.chatSendMode = ChatSendMode.CUSTOM_PAYLOAD;
        config.sendDelayMs = 0;
        Object connection = new Object();
        var service = new ChatSendService(config, keys, trust, null, null, cache,
                crypto, null, null, sent::add, ignored -> {}, () -> connection);

        service.resendLatest();
        service.tick();
        assertEquals(1, sent.size());
        trust.markDistrusted("Bob", identity);
        service.tick();
        trust.markTofuTrusted("Bob", identity);
        service.tick();
        assertEquals(1, sent.size(), "Revoked fragments must be cancelled, not resumed");

        service.resendLatest();
        keys.removePublicIdentity("Bob");
        service.tick();
        assertEquals(1, sent.size(), "Deleting the recipient must cancel queued work");

        keys.importPublicIdentity("Bob", original);
        service.resendLatest();
        keys.removePublicIdentity("Bob");
        trust.forget("Bob");
        var replacement = crypto.generateLocalKeys("Bob", "replacement", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(
                new PublicIdentity("Bob", "replacement", replacement.kemPublicKey(), replacement.signaturePublicKey())));
        service.tick();
        service.resendLatest();
        service.resend("cached");
        service.tick();
        assertEquals(1, sent.size(), "Replacement keys must reject both queued and cached old ciphertext");
    }

    /**
     * Verifies that legacy cache without fingerprint cannot be resent.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void legacyCacheWithoutFingerprintCannotBeResent() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(keys.ownPublicIdentity()));
        var cache = new SentMessageCacheService(root);
        cache.remember("legacy", "Bob", List.of("unbound-fragment"));
        assertNull(cache.find("legacy").orElseThrow().recipientFingerprint());
        var sent = new ArrayList<ChatSendFragment>();
        Object connection = new Object();
        var service = new ChatSendService(new Krypt04McgConfig(), keys, new KeyTrustService(root),
                null, null, cache, crypto, null, null, sent::add, ignored -> {}, () -> connection);
        service.resendLatest();
        service.resend("legacy");
        service.tick();
        assertTrue(sent.isEmpty());
    }
}
