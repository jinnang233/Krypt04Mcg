package dev.krypt04mcg.service;

import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class DataTransferServiceTest {
    @TempDir Path root;

    @Test void optInQueueDeliveryReplayAndDisable() throws Exception {
        var crypto = new CryptoService();
        var alice = new KeyStoreService(root.resolve("alice"), crypto);
        var bob = new KeyStoreService(root.resolve("bob"), crypto);
        alice.init("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        bob.init("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        alice.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(bob.ownPublicIdentity()));
        bob.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(alice.ownPublicIdentity()));
        var config = new Krypt04McgConfig();
        config.apiReceiver = "Bob";
        List<DataPayload> sent = new ArrayList<>();
        var sender = new DataTransferService(config, alice, new KeyTrustService(root.resolve("alice")), () -> true, sent::add);
        var receiver = new DataTransferService(config, bob, new KeyTrustService(root.resolve("bob")), () -> true, p -> {});
        byte[] bytes = {0, -1, -128, 42};
        assertThrows(IllegalStateException.class, () -> sender.send(null, "service:test", bytes));
        config.enableDataApi = true;
        var calls = new AtomicInteger();
        Krypt04McgApi.registerReceiver("service:test", data -> { assertArrayEquals(bytes, data); calls.incrementAndGet(); });
        try {
            sender.send(null, "service:test", bytes);
            assertThrows(IllegalStateException.class, () -> sender.send(null, "service:test", bytes));
            for (int i = 0; i < 10; i++) sender.tick();
            assertFalse(sent.isEmpty());
            for (var p : sent) receiver.receive(new DataPayload("Alice", p.fragment(), p.version()));
            assertEquals(1, calls.get());
            // Change fragment IDs to verify replay protection uses the signed message ID.
            String envelope = sent.stream().map(p -> p.fragment().split(":", 4)[3]).reduce("", String::concat);
            for (String p : OptionalTransferAssembler.split(envelope, FileTransferCodec.MAX_CHUNKS))
                receiver.receive(new DataPayload("Alice", p, 1));
            assertEquals(1, calls.get());
            sender.send(null, "service:test", bytes);
            config.enableDataApi = false;
            sender.tick();
            sent.clear();
            config.enableDataApi = true;
            sender.tick();
            assertTrue(sent.isEmpty());
        } finally { Krypt04McgApi.unregisterReceiver("service:test"); }
    }
}
