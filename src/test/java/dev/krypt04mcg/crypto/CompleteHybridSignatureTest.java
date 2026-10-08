package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class CompleteHybridSignatureTest {
    private static final Set<Class<?>> SPECS = Set.of(FalconParameterSpec.class, MLDSAParameterSpec.class,
            SLHDSAParameterSpec.class, SQIsignParameterSpec.class, SnovaParameterSpec.class);
    @TempDir Path directory;

    static Stream<SignatureAlgorithm> additions() {
        return Arrays.stream(SignatureAlgorithm.values()).filter(SignatureAlgorithm::customHybrid)
                .filter(a -> SPECS.contains(a.parameterSpec().getClass()));
    }

    static Stream<SignatureAlgorithm> representatives() {
        return Stream.of(SignatureAlgorithm.FALCON_512, SignatureAlgorithm.ML_DSA_65,
                        SignatureAlgorithm.SLH_DSA_SHA2_128F, SignatureAlgorithm.SLH_DSA_SHAKE_128F_WITH_SHAKE128,
                        SignatureAlgorithm.SQISIGN_LVL1, SignatureAlgorithm.SNOVA_24_5_4_SSK)
                .flatMap(a -> Stream.of("Ed25519", "Ed448")
                        .map(c -> SignatureAlgorithm.fromIdentifier(a.identifier() + "+" + c)));
    }

    @Test
    void everyPqcSelectionHasBothClassicalPairings() {
        assertEquals(152, additions().count());
        for (var base : SignatureAlgorithm.values()) {
            if (base.hybrid()) continue;
            for (String classical : new String[] {"Ed25519", "Ed448"}) {
                var hybrid = SignatureAlgorithm.fromIdentifier(base.identifier() + "+" + classical);
                assertEquals(base, hybrid.postQuantumComponent());
                assertEquals(classical, hybrid.classicalAlgorithm());
            }
        }
        for (var base : KemAlgorithm.values()) {
            if (base.hybrid()) continue;
            for (String classical : new String[] {"X25519", "X448"}) {
                var hybrid = KemAlgorithm.fromIdentifier(base.identifier() + "+" + classical);
                assertEquals(base, hybrid.postQuantumComponent());
                assertEquals(classical, hybrid.classicalAlgorithm());
            }
        }
    }

    @ParameterizedTest
    @MethodSource("additions")
    void everyNewSuiteSignsTransportsAndRequiresBothComponents(SignatureAlgorithm algorithm) throws Exception {
        var gson = JsonSupport.prettyGson();
        var config = gson.fromJson("{\"signatureAlgorithm\":\"" + algorithm.identifier() + "\"}", Krypt04McgConfig.class);
        assertEquals(algorithm, config.signatureAlgorithm);
        assertEquals(algorithm, gson.fromJson(gson.toJson(config), Krypt04McgConfig.class).signatureAlgorithm);
        assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier().toLowerCase(Locale.ROOT) + "/public"));
        assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "/private"));

        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_768_X25519, algorithm);
        var identity = crypto.validatePublicIdentity(identity(keys));
        var packet = crypto.encryptFor(identity, keys, "alice", "complete hybrid round trip", true);
        assertEquals(algorithm.identifier(), packet.algorithms().signature());
        var codec = new PacketCodec();
        var fragments = new FragmentService();
        var assembler = new FragmentReassembler();
        Optional<byte[]> assembled = Optional.empty();
        for (String fragment : fragments.fragment(codec.encode(packet), packet.messageId(), 180)) {
            assembled = assembler.accept(fragments.parse(fragment));
        }
        assertEquals("complete hybrid round trip", crypto.decrypt(codec.decode(assembled.orElseThrow()), keys, identity));

        byte[] badPq = packet.signature().clone();
        badPq[8] ^= 1;
        assertThrows(CryptoException.class, () -> crypto.decrypt(withSignature(packet, badPq), keys, identity));
        byte[] badClassical = packet.signature().clone();
        badClassical[badClassical.length - 1] ^= 1;
        assertThrows(CryptoException.class, () -> crypto.decrypt(withSignature(packet, badClassical), keys, identity));
        int pqSize = ByteBuffer.wrap(packet.signature(), 4, 4).getInt();
        for (byte[] incomplete : new byte[][] {
                Arrays.copyOfRange(packet.signature(), 8, 8 + pqSize),
                Arrays.copyOfRange(packet.signature(), 12 + pqSize, packet.signature().length),
                Arrays.copyOf(packet.signature(), packet.signature().length - 1),
                Arrays.copyOf(packet.signature(), packet.signature().length + 1)}) {
            assertThrows(CryptoException.class, () -> crypto.decrypt(withSignature(packet, incomplete), keys, identity));
        }

        // Generic factories may accept another PQ parameter set or pre-hash mode; the suite label must match.
        var otherCurve = SignatureAlgorithm.fromIdentifier(algorithm.postQuantumComponent().identifier()
                + (algorithm.classicalAlgorithm().equals("Ed25519") ? "+Ed448" : "+Ed25519"));
        assertThrows(CryptoException.class, () -> crypto.sign(relabel(keys.signaturePrivateKey(), otherCurve), new byte[] {1}));
        var otherPq = additions().filter(a -> a.parameterSpec().getClass() == algorithm.parameterSpec().getClass()
                && a.postQuantumComponent() != algorithm.postQuantumComponent()
                && a.classicalAlgorithm().equals(algorithm.classicalAlgorithm())).findFirst().orElseThrow();
        var wrongPublic = relabel(keys.signaturePublicKey(), otherPq);
        assertThrows(CryptoException.class, () -> crypto.validatePublicIdentity(
                new PublicIdentity("alice", "a", keys.kemPublicKey(), wrongPublic)));
    }

    @ParameterizedTest
    @MethodSource("representatives")
    void newFamiliesPersistAndCompleteSignedHandshakes(SignatureAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var store = new KeyStoreService(directory.resolve("keys"), crypto);
        store.init("alice", "a", KemAlgorithm.ML_KEM_768_X25519, algorithm);
        var reloaded = new KeyStoreService(directory.resolve("keys"), crypto);
        reloaded.init("alice", "a");
        assertEquals(store.local(), reloaded.local());
        var alice = reloaded.local();
        var bob = crypto.generateLocalKeys("bob", "b");
        var aliceSessions = new SessionService(directory.resolve("alice-session"));
        var bobSessions = new SessionService(directory.resolve("bob-session"));
        try (var initiator = new SessionHandshakeService(crypto, aliceSessions);
             var responder = new SessionHandshakeService(crypto, bobSessions)) {
            var request = initiator.begin(identity(bob), alice, KemAlgorithm.ML_KEM_512_X448, true, AeadAlgorithm.AES_256_GCM);
            var responses = new ArrayList<EncryptedPacket>();
            responder.complete(request, responder.decrypt(request, bob, identity(alice)), identity(alice), bob,
                    true, AeadAlgorithm.AES_256_GCM, (packet, receiver) -> responses.add(packet));
            var response = responses.getFirst();
            initiator.complete(response, initiator.decrypt(response, alice, identity(bob)), identity(bob), alice,
                    true, AeadAlgorithm.AES_256_GCM, (packet, receiver) -> fail("Unexpected extra response"));
            var aliceSession = aliceSessions.find("bob").orElseThrow();
            var bobSession = bobSessions.find("alice").orElseThrow();
            assertEquals(aliceSession.secret(), bobSession.secret());
            byte[] secret = Base64Url.decode(aliceSession.secret());
            var message = crypto.encryptWithSession("bob", "alice", secret, aliceSession.sessionId(), 1, "hybrid session", true,
                    AeadAlgorithm.CHACHA20_POLY1305);
            assertEquals("hybrid session", crypto.decryptWithSession(message, "bob", "alice", secret, bobSession.sessionId(), 1));
        }
    }

    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(), keys.kemPublicKey(), keys.signaturePublicKey());
    }

    private static KeyRecord relabel(KeyRecord key, SignatureAlgorithm algorithm) {
        String role = key.algorithm().endsWith("/private") ? "/private" : "/public";
        return new KeyRecord(algorithm.identifier() + role, key.owner(), key.uuid(), key.fingerprint(), key.createdAt(), key.keyData());
    }

    private static EncryptedPacket withSignature(EncryptedPacket packet, byte[] signature) {
        return new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(), packet.sender(), packet.receiver(),
                packet.timestampMillis(), packet.messageId(), packet.aadFragmentIndex(), packet.aadFragmentTotal(),
                packet.algorithms(), packet.nonce(), packet.kemCiphertext(), packet.ciphertext(), signature);
    }
}
