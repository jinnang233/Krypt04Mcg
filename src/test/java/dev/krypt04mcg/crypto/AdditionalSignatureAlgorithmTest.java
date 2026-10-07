package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.OptionalTransferAssembler;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import org.bouncycastle.pqc.jcajce.spec.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class AdditionalSignatureAlgorithmTest {
    @TempDir Path directory;
    private static final Set<Class<?>> SPECS = Set.of(MayoParameterSpec.class, HaetaeParameterSpec.class,
            UOVParameterSpec.class, QRUOVParameterSpec.class, AIMerParameterSpec.class, FaestParameterSpec.class,
            MQOMParameterSpec.class, SDitHParameterSpec.class);

    static Stream<SignatureAlgorithm> selections() {
        return Arrays.stream(SignatureAlgorithm.values())
                .filter(a -> a.parameterSpec() != null && SPECS.contains(a.parameterSpec().getClass()));
    }

    static Stream<SignatureAlgorithm> representatives() {
        return Stream.of(SignatureAlgorithm.MAYO_1_ED25519, SignatureAlgorithm.HAETAE_2_ED448,
                SignatureAlgorithm.UOV_IS_PKC_SKC_ED25519, SignatureAlgorithm.QRUOV_1Q127L3V156M54_ED448,
                SignatureAlgorithm.AIMER_128F_ED25519, SignatureAlgorithm.FAEST_128S_ED448,
                SignatureAlgorithm.MQOM2_CAT1_GF2_FAST_R3_ED25519, SignatureAlgorithm.SDITH_HYPERCUBE_CAT1_GF256_ED448);
    }

    @Test
    void exposesAllBcParameterSetsAndBothEdDsaPairings() throws Exception {
        var algorithms = selections().filter(a -> !a.customHybrid()).toList();
        assertEquals(97, algorithms.size());
        assertEquals(291, selections().count());
        for (Class<?> spec : SPECS) {
            var supported = new HashSet<>(algorithms.stream().filter(a -> a.parameterSpec().getClass() == spec)
                    .map(SignatureAlgorithm::parameterSpec).toList());
            for (var field : spec.getFields()) {
                if (field.getType() == spec) assertTrue(supported.remove(field.get(null)), field.getName());
            }
            assertTrue(supported.isEmpty());
        }
        for (var algorithm : algorithms) {
            for (String classical : new String[] {"Ed25519", "Ed448"}) {
                var hybrid = SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "+" + classical);
                assertEquals(algorithm, hybrid.postQuantumComponent());
                assertEquals(classical, hybrid.classicalAlgorithm());
            }
        }
    }

    @ParameterizedTest
    @MethodSource("selections")
    void everySelectionSignsValidatesAndTransports(SignatureAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_512, algorithm);
        var identity = crypto.validatePublicIdentity(identity(keys));
        var gson = JsonSupport.prettyGson();
        var config = gson.fromJson("{\"signatureAlgorithm\":\"" + algorithm.identifier() + "\"}", Krypt04McgConfig.class);
        assertEquals(algorithm, config.signatureAlgorithm);
        assertEquals(algorithm, gson.fromJson(gson.toJson(config), Krypt04McgConfig.class).signatureAlgorithm);
        assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier().toLowerCase(Locale.ROOT) + "/public"));
        assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "/private"));

        var packet = crypto.encryptFor(identity, keys, "alice", "additional signature round trip", true);
        var codec = new PacketCodec();
        var fragments = new FragmentService();
        var assembler = new FragmentReassembler();
        Optional<byte[]> assembled = Optional.empty();
        for (String fragment : fragments.fragment(codec.encode(packet), packet.messageId(), 180)) {
            assembled = assembler.accept(fragments.parse(fragment));
        }
        assertEquals("additional signature round trip", crypto.decrypt(codec.decode(assembled.orElseThrow()), keys, identity));
        byte[] signature = packet.signature().clone();
        // Corrupt the PQ component, preserving framing and the classical signature.
        signature[algorithm.customHybrid() ? 8 : 0] ^= 1;
        assertThrows(CryptoException.class, () -> crypto.decrypt(withSignature(packet, signature), keys, identity));
        if (algorithm.customHybrid()) {
            byte[] badClassical = packet.signature().clone();
            badClassical[badClassical.length - 1] ^= 1;
            assertThrows(CryptoException.class, () -> crypto.decrypt(withSignature(packet, badClassical), keys, identity));
        }
    }

    @ParameterizedTest
    @MethodSource("representatives")
    void hybridsPersistRejectRelabelingAndCompleteHandshakes(SignatureAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var store = new KeyStoreService(directory.resolve("keys"), crypto);
        store.init("alice", "a", KemAlgorithm.ML_KEM_768_X25519, algorithm);
        var reloaded = new KeyStoreService(directory.resolve("keys"), crypto);
        reloaded.init("alice", "a");
        assertEquals(store.local(), reloaded.local());
        var alice = reloaded.local();
        var other = algorithm.classicalAlgorithm().equals("Ed25519")
                ? SignatureAlgorithm.MAYO_1_ED448 : SignatureAlgorithm.MAYO_1_ED25519;
        KeyRecord wrongPrivate = relabel(alice.signaturePrivateKey(), other.identifier() + "/private");
        KeyRecord wrongPublic = relabel(alice.signaturePublicKey(), other.identifier() + "/public");
        assertThrows(CryptoException.class, () -> crypto.sign(wrongPrivate, new byte[] {1}));
        assertThrows(CryptoException.class, () -> crypto.validatePublicIdentity(
                new PublicIdentity("alice", "a", alice.kemPublicKey(), wrongPublic)));

        var bob = crypto.generateLocalKeys("bob", "b");
        var aliceSessions = new SessionService(directory.resolve("alice-session"));
        var bobSessions = new SessionService(directory.resolve("bob-session"));
        try (var initiator = new SessionHandshakeService(crypto, aliceSessions);
             var responder = new SessionHandshakeService(crypto, bobSessions)) {
            var request = initiator.begin(identity(bob), alice, KemAlgorithm.ML_KEM_768_X25519, true, AeadAlgorithm.AES_256_GCM);
            var responses = new ArrayList<EncryptedPacket>();
            responder.complete(request, responder.decrypt(request, bob, identity(alice)), identity(alice), bob,
                    true, AeadAlgorithm.AES_256_GCM, (packet, receiver) -> responses.add(packet));
            var response = responses.getFirst();
            initiator.complete(response, initiator.decrypt(response, alice, identity(bob)), identity(bob), alice,
                    true, AeadAlgorithm.AES_256_GCM, (packet, receiver) -> fail("Unexpected extra response"));
            assertEquals(aliceSessions.find("bob").orElseThrow().secret(), bobSessions.find("alice").orElseThrow().secret());
        }
    }

    @Test
    void malformedSignaturesAndComponentSplicingAreRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        var algorithm = SignatureAlgorithm.MAYO_1_ED25519;
        var keys = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_512, algorithm);
        var other = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_512, algorithm);
        byte[] input = {1, 2, 3};
        byte[] signature = crypto.sign(keys.signaturePrivateKey(), input);
        assertFalse(crypto.verify(keys.signaturePublicKey(), new byte[] {1, 2, 4}, signature));
        int pqSize = ByteBuffer.wrap(signature, 4, 4).getInt();
        for (byte[] bad : new byte[][] {new byte[0], new byte[8], Arrays.copyOf(signature, signature.length - 1),
                Arrays.copyOf(signature, signature.length + 1), Arrays.copyOfRange(signature, 8, 8 + pqSize)}) {
            assertFalse(crypto.verify(keys.signaturePublicKey(), input, bad));
        }
        byte[] negativeLength = signature.clone();
        ByteBuffer.wrap(negativeLength, 4, 4).putInt(-1);
        assertFalse(crypto.verify(keys.signaturePublicKey(), input, negativeLength));

        var publicKey = (SignatureCrypto.HybridPublicKey) SignatureCrypto.decodePublic(algorithm,
                Base64Url.decode(keys.signaturePublicKey().keyData()));
        var otherPublic = (SignatureCrypto.HybridPublicKey) SignatureCrypto.decodePublic(algorithm,
                Base64Url.decode(other.signaturePublicKey().keyData()));
        var privateKey = (SignatureCrypto.HybridPrivateKey) SignatureCrypto.decodePrivate(algorithm,
                Base64Url.decode(keys.signaturePrivateKey().keyData()));
        var otherPrivate = (SignatureCrypto.HybridPrivateKey) SignatureCrypto.decodePrivate(algorithm,
                Base64Url.decode(other.signaturePrivateKey().keyData()));
        var splicedPublic = new SignatureCrypto.HybridPublicKey(publicKey.pq(), otherPublic.classical());
        var splicedPrivate = new SignatureCrypto.HybridPrivateKey(privateKey.pq(), otherPrivate.classical(), splicedPublic);
        byte[] spliced = SignatureCrypto.sign(algorithm, splicedPrivate, input, new java.security.SecureRandom());
        int splicedPqSize = ByteBuffer.wrap(spliced, 4, 4).getInt();
        // The PQ key and message are the same, but the public-key pair commitment differs.
        System.arraycopy(spliced, 8, signature, 8, splicedPqSize);
        assertFalse(crypto.verify(keys.signaturePublicKey(), input, signature));
        var mismatchedPrivate = crypto.keyRecord(algorithm.identifier() + "/private", "alice", "a",
                keys.signaturePrivateKey().createdAt(), splicedPrivate.getEncoded());
        assertThrows(CryptoException.class, () -> crypto.validateLocalKeyMaterial(new LocalKeyMaterial(
                keys.kemPublicKey(), keys.kemPrivateKey(), keys.signaturePublicKey(), mismatchedPrivate), "alice", "a"));
    }

    @Test
    void largestUovPublicIdentityFitsOptionalKeySharing() throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("alice", "a", KemAlgorithm.CMCE_MCELIECE8192128_X448, SignatureAlgorithm.UOV_V_ED448);
        var json = JsonSupport.prettyGson().toJson(identity(keys));
        var parts = OptionalTransferAssembler.split(json, OptionalTransferAssembler.MAX_KEY_CHUNKS);
        assertTrue(parts.size() > 256);
        var assembler = new OptionalTransferAssembler(OptionalTransferAssembler.MAX_KEY_CHUNKS, 4);
        Optional<String> assembled = Optional.empty();
        for (String part : parts) assembled = assembler.accept("alice", part, 1000);
        var imported = crypto.validatePublicIdentity(JsonSupport.prettyGson().fromJson(assembled.orElseThrow(), PublicIdentity.class));
        assertEquals(keys.signaturePublicKey().fingerprint(), imported.signaturePublicKey().fingerprint());
        crypto.validateLocalKeyMaterial(keys, "alice", "a");
    }

    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(), keys.kemPublicKey(), keys.signaturePublicKey());
    }

    private static KeyRecord relabel(KeyRecord key, String algorithm) {
        return new KeyRecord(algorithm, key.owner(), key.uuid(), key.fingerprint(), key.createdAt(), key.keyData());
    }

    private static EncryptedPacket withSignature(EncryptedPacket packet, byte[] signature) {
        return new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(), packet.sender(), packet.receiver(),
                packet.timestampMillis(), packet.messageId(), packet.aadFragmentIndex(), packet.aadFragmentTotal(),
                packet.algorithms(), packet.nonce(), packet.kemCiphertext(), packet.ciphertext(), signature);
    }
}
