package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.ChatSendFragment;
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

    @Test void cachedResendRechecksCurrentTrust() throws Exception {
        var crypto = new CryptoService();
        var keys = new KeyStoreService(root, crypto);
        keys.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var identity = keys.ownPublicIdentity();
        keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(identity));
        var trust = new KeyTrustService(root);
        var cache = new SentMessageCacheService(root);
        cache.remember("cached", "Bob", List.of("encrypted-fragment"));
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
}
