package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class HybridCryptoTest {
    @TempDir Path directory;

    /**
     * Provides the signatures fixture operation used by the hybrid crypto test regression scenarios.
     *
     * @return the result described above
     */
    static Stream<SignatureAlgorithm> signatures() {
        return Arrays.stream(SignatureAlgorithm.values()).filter(SignatureAlgorithm::nativeHybrid);
    }

    /**
     * Verifies that native signatures validate round trip and reject tampering.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @ParameterizedTest
    @MethodSource("signatures")
    void nativeSignaturesValidateRoundTripAndRejectTampering(SignatureAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("alice", "a", KemAlgorithm.ML_KEM_512, algorithm);
        crypto.validateLocalKeyMaterial(keys, "alice", "a");
        var identity = crypto.validatePublicIdentity(identity(keys));
        byte[] input = {1, 2, 3};
        byte[] signature = crypto.sign(keys.signaturePrivateKey(), input);
        // Interoperability: verify directly through BC, without the mod's signature helper.
        /*
         * Selects the exact named signature implementation and provider, preserving suite-specific
         * prehash/composite behavior. Key parameters are validated separately; a missing or unsupported
         * implementation is an error, not permission to downgrade.
         */
        var verifier = Signature.getInstance(algorithm.jcaName(), "BC");
        /*
         * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
         * insufficient: the decoded parameter set and recorded public/private role are checked separately
         * before cryptographic use.
         *
         * Wraps a SubjectPublicKeyInfo-style encoding for the selected provider. Encoded algorithm identifiers
         * and decoded parameter sets must agree with the declared suite; parsing does not establish a trusted
         * owner.
         */
        verifier.initVerify(KeyFactory.getInstance(algorithm.jcaName(), "BC").generatePublic(
                new X509EncodedKeySpec(Base64Url.decode(keys.signaturePublicKey().keyData()))));
        verifier.update(input);
        assertTrue(verifier.verify(signature));
        assertFalse(crypto.verify(keys.signaturePublicKey(), new byte[] {1, 2, 4}, signature));
        assertEquals(algorithm, JsonSupport.prettyGson().fromJson(
                JsonSupport.prettyGson().toJson(algorithm), SignatureAlgorithm.class));
        var packet = crypto.encryptFor(identity, keys, "alice", "hybrid signature", true);
        assertEquals("hybrid signature", crypto.decrypt(packet, keys, identity));
        signature[signature.length - 1] ^= 1;
        assertFalse(crypto.verify(keys.signaturePublicKey(), input, signature));
    }

    /**
     * Provides the handshake kems fixture operation used by the hybrid crypto test regression scenarios.
     *
     * @return the result described above
     */
    static Stream<KemAlgorithm> handshakeKems() {
        return Stream.of(KemAlgorithm.ML_KEM_768_X25519, KemAlgorithm.ML_KEM_1024_X448,
                KemAlgorithm.ML_KEM_512_X25519, KemAlgorithm.SNTRUPRIME_SNTRUP653_X448);
    }

    /**
     * Verifies that hybrid handshake persists keys and creates usable session.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @ParameterizedTest
    @MethodSource("handshakeKems")
    void hybridHandshakePersistsKeysAndCreatesUsableSession(KemAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var store = new KeyStoreService(directory.resolve("alice"), crypto);
        store.init("alice", "a", algorithm, SignatureAlgorithm.MLDSA44_ED25519_SHA512);
        var reloaded = new KeyStoreService(directory.resolve("alice"), crypto);
        reloaded.init("alice", "a", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_512);
        assertEquals(store.local(), reloaded.local());
        var alice = reloaded.local();
        var bob = crypto.generateLocalKeys("bob", "b",
                algorithm == KemAlgorithm.ML_KEM_768_X25519 ? KemAlgorithm.ML_KEM_512_X448 : KemAlgorithm.ML_KEM_768_X25519,
                SignatureAlgorithm.MLDSA87_ED448_SHAKE256);
        var aliceSessions = new SessionService(directory.resolve("alice-sessions"));
        var bobSessions = new SessionService(directory.resolve("bob-sessions"));
        try (var initiator = new SessionHandshakeService(crypto, aliceSessions);
             var responder = new SessionHandshakeService(crypto, bobSessions)) {
            var request = initiator.begin(identity(bob), alice, algorithm, true, AeadAlgorithm.CHACHA20_POLY1305);
            var responses = new ArrayList<EncryptedPacket>();
            responder.complete(request, responder.decrypt(request, bob, identity(alice)), identity(alice), bob,
                    true, AeadAlgorithm.CHACHA20_POLY1305, (packet, receiver) -> responses.add(packet));
            var response = new PacketCodec().decode(new PacketCodec().encode(responses.getFirst()));
            assertEquals(algorithm.identifier(), response.algorithms().kem());
            initiator.complete(response, initiator.decrypt(response, alice, identity(bob)), identity(bob), alice,
                    true, AeadAlgorithm.CHACHA20_POLY1305, (packet, receiver) -> fail("Unexpected reply"));
            var aliceSession = aliceSessions.find("bob").orElseThrow();
            var bobSession = bobSessions.find("alice").orElseThrow();
            assertEquals(aliceSession.secret(), bobSession.secret());
            byte[] secret = Base64Url.decode(aliceSession.secret());
            var message = crypto.encryptWithSession("bob", "alice", secret, aliceSession.sessionId(), 1,
                    "hybrid session", false, AeadAlgorithm.CHACHA20_POLY1305);
            assertEquals("hybrid session", crypto.decryptWithSession(message, "bob", "alice", secret,
                    bobSession.sessionId(), 1));
            assertThrows(Exception.class, () -> initiator.decrypt(response, alice, identity(bob)));
        }
    }

    /**
     * Verifies that tampered hybrid ciphertexts never fall back to single kem.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @ParameterizedTest
    @MethodSource("handshakeKems")
    void tamperedHybridCiphertextsNeverFallBackToSingleKem(KemAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("alice", "a", algorithm, SignatureAlgorithm.ML_DSA_44);
        var packet = crypto.encryptFor(identity(keys), keys, "alice", "unsigned hybrid", false);
        assertEquals("unsigned hybrid", crypto.decrypt(packet, keys, null));
        // Tamper both component regions, even in unsigned packets.
        for (int offset : new int[] {packet.kemCiphertext().length / 2, packet.kemCiphertext().length - 1}) {
            byte[] ciphertext = packet.kemCiphertext().clone();
            ciphertext[offset] ^= 1;
            assertThrows(CryptoException.class, () -> crypto.decrypt(withCiphertext(packet, ciphertext), keys, null));
        }
        if (!algorithm.nativeHybrid()) {
            // Well-formed framing containing an undersized PQ encapsulation still fails cleanly.
            byte[] original = packet.kemCiphertext();
            int pqSize = ByteBuffer.wrap(original, 4, 4).getInt();
            byte[] classical = Arrays.copyOfRange(original, 8 + pqSize, original.length);
            byte[] undersized = ByteBuffer.allocate(9 + classical.length)
                    .putInt(ByteBuffer.wrap(original).getInt()).putInt(1).put(original[8]).put(classical).array();
            assertThrows(CryptoException.class, () -> crypto.decrypt(withCiphertext(packet, undersized), keys, null));
        }
        for (byte[] ciphertext : new byte[][] {new byte[0], new byte[8],
                Arrays.copyOf(packet.kemCiphertext(), packet.kemCiphertext().length - 1),
                Arrays.copyOf(packet.kemCiphertext(), packet.kemCiphertext().length + 1)}) {
            assertThrows(CryptoException.class, () -> crypto.decrypt(withCiphertext(packet, ciphertext), keys, null));
        }
    }

    /**
     * Verifies that rejects low order points relabeled keys and mismatched components.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void rejectsLowOrderPointsRelabeledKeysAndMismatchedComponents() throws Exception {
        CryptoService crypto = new CryptoService();
        for (KemAlgorithm algorithm : new KemAlgorithm[] {KemAlgorithm.ML_KEM_512_X25519, KemAlgorithm.ML_KEM_512_X448}) {
            var keys = crypto.generateLocalKeys("alice", "a", algorithm, SignatureAlgorithm.MLDSA44_ED25519_SHA512);
            byte[] encoded = Base64Url.decode(keys.kemPublicKey().keyData());
            int size = algorithm.classicalAlgorithm().equals("X25519") ? 32 : 56;
            Arrays.fill(encoded, encoded.length - size, encoded.length, (byte) 0);
            var lowOrder = crypto.keyRecord(keys.kemPublicKey().algorithm(), "alice", "a",
                    keys.kemPublicKey().createdAt(), encoded);
            assertThrows(CryptoException.class, () -> crypto.validatePublicIdentity(
                    new PublicIdentity("alice", "a", lowOrder, keys.signaturePublicKey())));
            var relabeled = relabel(keys.kemPublicKey(), "ML-KEM-1024+" + algorithm.classicalAlgorithm() + "/public");
            assertThrows(CryptoException.class, () -> crypto.encryptFor(
                    new PublicIdentity("alice", "a", relabeled, keys.signaturePublicKey()), keys, "alice", "x", false));
            var other = crypto.generateLocalKeys("alice", "a", algorithm, SignatureAlgorithm.ML_DSA_44);
            byte[] mixed = Base64Url.decode(keys.kemPrivateKey().keyData());
            byte[] otherEncoded = Base64Url.decode(other.kemPrivateKey().keyData());
            // Replace just the classical secret, preserving the PQ key pair and public key.
            int position = 4 + 4 + ByteBuffer.wrap(mixed, 4, 4).getInt() + 4;
            int otherPosition = 4 + 4 + ByteBuffer.wrap(otherEncoded, 4, 4).getInt() + 4;
            System.arraycopy(otherEncoded, otherPosition, mixed, position, size);
            var mixedPrivate = crypto.keyRecord(keys.kemPrivateKey().algorithm(), "alice", "a",
                    keys.kemPrivateKey().createdAt(), mixed);
            assertThrows(CryptoException.class, () -> crypto.validateLocalKeyMaterial(
                    new LocalKeyMaterial(keys.kemPublicKey(), mixedPrivate, keys.signaturePublicKey(), keys.signaturePrivateKey()),
                    "alice", "a"));
            assertThrows(CryptoException.class, () -> crypto.sign(relabel(keys.signaturePrivateKey(),
                    "MLDSA65-Ed25519-SHA512/private"), new byte[] {1}));
        }
    }

    /**
     * Provides the identity fixture operation used by the hybrid crypto test regression scenarios.
     *
     * @param keys the keys supplied to this operation
     * @return the result described above
     */
    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(),
                keys.kemPublicKey(), keys.signaturePublicKey());
    }

    /**
     * Provides the relabel fixture operation used by the hybrid crypto test regression scenarios.
     *
     * @param key the cryptographic key material for this operation
     * @param algorithm the selected algorithm and parameter-set definition
     * @return the result described above
     */
    private static KeyRecord relabel(KeyRecord key, String algorithm) {
        return new KeyRecord(algorithm, key.owner(), key.uuid(), key.fingerprint(), key.createdAt(), key.keyData());
    }

    /**
     * Provides the with ciphertext fixture operation used by the hybrid crypto test regression scenarios.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @return the result described above
     */
    private static EncryptedPacket withCiphertext(EncryptedPacket packet, byte[] ciphertext) {
        return new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(), packet.sender(),
                packet.receiver(), packet.timestampMillis(), packet.messageId(), packet.aadFragmentIndex(),
                packet.aadFragmentTotal(), packet.algorithms(), packet.nonce(), ciphertext, packet.ciphertext(), packet.signature());
    }
}
