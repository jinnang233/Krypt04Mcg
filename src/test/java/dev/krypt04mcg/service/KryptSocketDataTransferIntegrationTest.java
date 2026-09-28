package dev.krypt04mcg.service;

import static org.junit.jupiter.api.Assertions.*;
import dev.krypt04mcg.api.*;
import dev.krypt04mcg.api.KryptStreamRegistry.Frame;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.util.JsonSupport;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/** Real session handshake + AEAD + multiplexers over bounded ordered payload links. */
@Timeout(180)
class KryptSocketDataTransferIntegrationTest {
    @TempDir Path root;

    @Test void directFramesNeverEnterReliableDataTransferPipeline() throws Exception {
        try (var pair = new Pair()) {
            var sockets = pair.open("direct");
            byte[] expected = new byte[2 * 1024 * 1024]; new Random(7).nextBytes(expected);
            var read = async(() -> sockets.remote.getInputStream().readNBytes(expected.length));
            sockets.local.getOutputStream().write(expected);
            assertArrayEquals(expected, read.get(120, TimeUnit.SECONDS));
            pair.assertHealthy();
            assertEquals(0, pair.alice.data.pipelineStats().waitingAck());
            assertEquals(0, pair.bob.data.pipelineStats().pending());
            assertEquals(0, pair.reliablePayloads.get());
            assertFalse(sockets.local.isClosed());
            assertFalse(sockets.remote.isClosed());
        }
    }

    @Test void replayOrTamperDoesNotAdvanceCounterOrDeliverDuplicateBytes() throws Exception {
        try (var pair = new Pair()) {
            var sockets = pair.open("security");
            sockets.local.getOutputStream().write(new byte[] {1});
            assertEquals(1, sockets.remote.getInputStream().read());
            TunnelPayload captured = pair.lastAlice.get();
            // Pause the ordered link while directly exercising rejection on its consumer.
            assertThrows(Exception.class, () -> pair.bob.tunnel.receive(captured));
            byte[] changed = captured.envelope().clone(); changed[changed.length - 1] ^= 1;
            assertThrows(Exception.class, () -> pair.bob.tunnel.receive(new TunnelPayload("Alice", changed)));
            sockets.local.getOutputStream().write(new byte[] {2});
            assertEquals(2, sockets.remote.getInputStream().read());
            pair.assertHealthy();
        }
    }

    static <T> FutureTask<T> async(Callable<T> action) {
        var task = new FutureTask<>(action); Thread.ofVirtual().start(task); return task;
    }
    record Sockets(KryptSocket local, KryptSocket remote) {}

    final class Pair implements AutoCloseable {
        final Krypt04McgConfig config = new Krypt04McgConfig();
        final AtomicInteger reliablePayloads = new AtomicInteger();
        final AtomicReference<Throwable> error = new AtomicReference<>();
        final AtomicReference<TunnelPayload> lastAlice = new AtomicReference<>();
        final Endpoint alice, bob;
        Pair() throws Exception {
            config.enableDataApi = true;
            config.socketMaxBufferedMiB = 1;
            alice = new Endpoint("Alice", "Bob");
            bob = new Endpoint("Bob", "Alice");
            alice.keys.importPublicIdentity("Bob", JsonSupport.prettyGson().toJson(bob.keys.ownPublicIdentity()));
            bob.keys.importPublicIdentity("Alice", JsonSupport.prettyGson().toJson(alice.keys.ownPublicIdentity()));
            var request = alice.handshake.begin(bob.keys.ownPublicIdentity(), alice.keys.local(),
                    KemAlgorithm.ML_KEM_768, false, AeadAlgorithm.AES_256_GCM);
            var response = new AtomicReference<EncryptedPacket>();
            bob.handshake.complete(request, bob.handshake.decrypt(request, bob.keys.local(), alice.keys.ownPublicIdentity()),
                    alice.keys.ownPublicIdentity(), bob.keys.local(), false, AeadAlgorithm.AES_256_GCM,
                    (packet, peer) -> response.set(packet));
            alice.handshake.complete(response.get(), alice.handshake.decrypt(response.get(), alice.keys.local(), bob.keys.ownPublicIdentity()),
                    bob.keys.ownPublicIdentity(), alice.keys.local(), false, AeadAlgorithm.AES_256_GCM,
                    (packet, peer) -> fail("Unexpected handshake response"));
            alice.start(bob); bob.start(alice);
        }

        Sockets open(String channel) throws Exception {
            var accepted = new CompletableFuture<KryptSocket>();
            bob.streams.listen(channel, accepted::complete);
            KryptSocket local = alice.streams.connect(alice.tunnel.attach(alice.data.connect("Bob")), channel);
            return new Sockets(local, accepted.get(15, TimeUnit.SECONDS));
        }
        void assertHealthy() { assertNull(error.get(), () -> String.valueOf(error.get())); }
        @Override public void close() { alice.close(); bob.close(); }

        final class Endpoint implements AutoCloseable {
            final String name, peer;
            final Path directory;
            final KeyStoreService keys;
            final KeyTrustService trust;
            final SessionService sessions;
            final SessionHandshakeService handshake;
            final KryptStreamTestEndpoint streams = new KryptStreamTestEndpoint();
            final ArrayBlockingQueue<TunnelPayload> incoming = new ArrayBlockingQueue<>(2);
            final DataTransferService data;
            TunnelService tunnel;
            Thread reader;
            Endpoint(String name, String peer) throws Exception {
                this.name = name; this.peer = peer;
                directory = root.resolve(name);
                var crypto = new CryptoService();
                keys = new KeyStoreService(directory, crypto);
                keys.init(name, name, KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
                trust = new KeyTrustService(directory);
                sessions = new SessionService(directory);
                handshake = new SessionHandshakeService(crypto, sessions);
                data = new DataTransferService(config, keys, trust, sessions, handshake, () -> true,
                        payload -> reliablePayloads.incrementAndGet());
                streams.configure(config);
            }
            void start(Endpoint other) {
                tunnel = new TunnelService(config, keys, trust, sessions, new TunnelCounters(directory),
                        payload -> {
                            var forwarded = new TunnelPayload(name, payload.envelope());
                            if (name.equals("Alice")) lastAlice.set(forwarded);
                            other.incoming.put(forwarded);
                        }, streams::receive);
                reader = Thread.ofVirtual().name("test-receive-" + name).start(() -> {
                    try { while (!Thread.currentThread().isInterrupted()) tunnel.receive(incoming.take()); }
                    catch (InterruptedException expected) { Thread.currentThread().interrupt(); }
                    catch (Throwable e) { error.set(e); streams.clear(); }
                });
            }
            @Override public void close() {
                streams.clear();
                if (reader != null) reader.interrupt();
                if (tunnel != null) tunnel.close();
                data.close(); handshake.close();
            }
        }
    }
}
