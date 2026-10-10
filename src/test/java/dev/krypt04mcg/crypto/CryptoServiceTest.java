package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CryptoServiceTest {
    /**
     * Verifies that rejects valid signatures under another players name.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void rejectsValidSignaturesUnderAnotherPlayersName() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial mallory = crypto.generateLocalKeys("mallory", "mallory-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), mallory, "alice", "forged", true);
        assertThrows(CryptoException.class, () -> crypto.decrypt(packet, bob, publicIdentity(mallory)));
        byte[] secret = new byte[32];
        EncryptedPacket session = crypto.encryptWithSession("bob", "alice", secret, "AAAAAAAAAAAAAAAAAAAAAA", 0, "forged", false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);
        assertThrows(CryptoException.class,
                () -> crypto.decryptWithSession(session, "bob", "mallory", secret, "AAAAAAAAAAAAAAAAAAAAAA", 0));
    }

    /**
     * Verifies that encrypt decrypt and sign verify.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void encryptDecryptAndSignVerify() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "hello bob", true);
        String plaintext = crypto.decrypt(packet, bob, publicIdentity(alice));

        assertEquals("hello bob", plaintext);
        assertEquals("ML-KEM-768+X25519/public", alice.kemPublicKey().algorithm());
        assertEquals("ML-KEM-768+X25519/private", bob.kemPrivateKey().algorithm());
        assertEquals("ML-KEM-768+X25519", packet.algorithms().kem());
        assertEquals("MLDSA65-Ed25519-SHA512", packet.algorithms().signature());
        assertTrue(packet.signed());
    }

    /**
     * Verifies that null algorithm selections use hybrid defaults.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void nullAlgorithmSelectionsUseHybridDefaults() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial keys = crypto.generateLocalKeys("alice", "alice-uuid", null, null);
        assertEquals("ML-KEM-768+X25519/public", keys.kemPublicKey().algorithm());
        assertEquals("MLDSA65-Ed25519-SHA512/public", keys.signaturePublicKey().algorithm());
        try (var ephemeral = crypto.generateEphemeralKemKeyPair(null)) {
            assertEquals(KemAlgorithm.ML_KEM_768_X25519, ephemeral.algorithm());
        }
    }

    /**
     * Verifies that wrong receiver is rejected.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void wrongReceiverIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        LocalKeyMaterial charlie = crypto.generateLocalKeys("charlie", "charlie-uuid");

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "hello bob", false);

        assertThrows(CryptoException.class, () -> crypto.decrypt(packet, charlie, publicIdentity(alice)));
    }

    /**
     * Verifies that modified ciphertext is rejected.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void modifiedCiphertextIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "hello bob", true);
        byte[] changed = packet.ciphertext().clone();
        changed[0] ^= 0x01;
        EncryptedPacket tampered = new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(),
                packet.sender(), packet.receiver(), packet.timestampMillis(), packet.messageId(),
                packet.aadFragmentIndex(), packet.aadFragmentTotal(), packet.algorithms(), packet.nonce(),
                packet.kemCiphertext(), changed, packet.signature());

        assertThrows(CryptoException.class, () -> crypto.decrypt(tampered, bob, publicIdentity(alice)));
    }

    /**
     * Verifies that compressed messages round trip.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void compressedMessagesRoundTrip() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        String message = "hello bob ".repeat(80);

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", message, true, true);
        String plaintext = crypto.decrypt(packet, bob, publicIdentity(alice));

        assertEquals(message, plaintext);
        assertTrue((packet.flags() & CryptoService.FLAG_COMPRESSED) != 0);
    }

    /**
     * Verifies that packet and key records select mixed post quantum parameter sets.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void packetAndKeyRecordsSelectMixedPostQuantumParameterSets() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid",
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_1024);

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "mixed suite", true,
                false, AeadAlgorithm.CHACHA20_POLY1305);

        assertEquals("ML-KEM-768", packet.algorithms().kem());
        assertEquals("ML-DSA-44", packet.algorithms().signature());
        assertEquals("ChaCha20-Poly1305", packet.algorithms().aead());
        assertEquals("mixed suite", crypto.decrypt(packet, bob, publicIdentity(alice)));
    }

    /**
     * Verifies that compressed empty message round trips.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void compressedEmptyMessageRoundTrips() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "", true, true);
        String plaintext = crypto.decrypt(packet, bob, publicIdentity(alice));

        assertEquals("", plaintext);
        assertTrue((packet.flags() & CryptoService.FLAG_COMPRESSED) != 0);
    }

    /**
     * Verifies that session messages use session secret.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void sessionMessagesUseSessionSecret() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        byte[] sessionSecret = new byte[32];
        new SecureRandom().nextBytes(sessionSecret);

        EncryptedPacket packet = crypto.encryptWithSession("bob", "alice", sessionSecret, "AAAAAAAAAAAAAAAAAAAAAA", 0,
                "hello over session", true, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);
        String plaintext = crypto.decryptWithSession(packet, "bob", "alice", sessionSecret, "AAAAAAAAAAAAAAAAAAAAAA", 0);

        assertEquals(PacketType.SESSION_MESSAGE, packet.type());
        assertEquals(0, packet.kemCiphertext().length);
        assertEquals("hello over session", plaintext);
        assertTrue(packet.ciphertext().length > 0);
    }

    /**
     * Verifies that session message with wrong secret is rejected.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void sessionMessageWithWrongSecretIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        byte[] sessionSecret = new byte[32];
        byte[] wrongSecret = new byte[32];
        new SecureRandom().nextBytes(sessionSecret);
        new SecureRandom().nextBytes(wrongSecret);

        EncryptedPacket packet = crypto.encryptWithSession("bob", "alice", sessionSecret, "AAAAAAAAAAAAAAAAAAAAAA", 0,
                "hello over session", false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);

        assertThrows(CryptoException.class, () ->
                crypto.decryptWithSession(packet, "bob", "alice", wrongSecret, "AAAAAAAAAAAAAAAAAAAAAA", 0));
    }

    /**
     * Verifies that oversized plaintext encryption is rejected.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void oversizedPlaintextEncryptionIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        String message = "A".repeat(CryptoService.MAX_PLAINTEXT_BYTES + 1);

        assertThrows(CryptoException.class, () ->
                crypto.encryptFor(publicIdentity(bob), alice, "alice", message, true, true));
    }

    /**
     * Verifies that oversized compressed payload inflation is rejected.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void oversizedCompressedPayloadInflationIsRejected() throws Exception {
        Method inflate = CryptoService.class.getDeclaredMethod("inflate", byte[].class);
        inflate.setAccessible(true);
        byte[] compressed = deflate("A".repeat(CryptoService.MAX_PLAINTEXT_BYTES + 1).getBytes());

        InvocationTargetException exception = assertThrows(InvocationTargetException.class, () ->
                inflate.invoke(new CryptoService(), (Object) compressed));

        assertTrue(exception.getCause() instanceof CryptoException);
    }

    /**
     * Verifies that oversized uncompressed decryption is rejected.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void oversizedUncompressedDecryptionIsRejected() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        byte[] secret = new byte[32];
        EncryptedPacket template = crypto.encryptWithSession("bob", "bob", secret, "AAAAAAAAAAAAAAAAAAAAAA", 0, "", false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);
        var codec = new dev.krypt04mcg.protocol.PacketCodec();
        /*
         * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
         * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
         * provider or tag failure.
         */
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(crypto.deriveSessionSecret(secret, template.messageId()), "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, template.nonce()));
        /*
         * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
         * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
         * tag.
         */
        cipher.updateAAD(codec.aadFor(template));
        /*
         * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
         * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
         * output when finalization fails.
         */
        byte[] ciphertext = cipher.doFinal(new byte[CryptoService.MAX_PLAINTEXT_BYTES + 1]);
        EncryptedPacket oversized = new EncryptedPacket(template.protocolVersion(), template.type(), template.flags(),
                template.sender(), template.receiver(), template.timestampMillis(), template.messageId(),
                template.aadFragmentIndex(), template.aadFragmentTotal(), template.algorithms(), template.nonce(),
                template.kemCiphertext(), ciphertext, template.signature(), template.sessionId(), template.sequence());
        assertThrows(CryptoException.class,
                () -> crypto.decryptWithSession(oversized, "bob", "bob", secret, "AAAAAAAAAAAAAAAAAAAAAA", 0));
    }

    /**
     * Provides the public identity fixture operation used by the crypto service test regression scenarios.
     *
     * @param material the material supplied to this operation
     * @return the result described above
     */
    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }

    /**
     * Provides the deflate fixture operation used by the crypto service test regression scenarios.
     *
     * @param plaintext the plaintext bytes to encrypt or process
     * @return the resulting array produced by this operation
     */
    private static byte[] deflate(byte[] plaintext) {
        /*
         * Uses JDK DEFLATE after plaintext size admission and releases compressor resources in the surrounding
         * lifecycle. Compression changes visible ciphertext length and is not an authentication or
         * confidentiality primitive.
         */
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(plaintext);
        deflater.finish();
        byte[] buffer = new byte[512];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            out.write(buffer, 0, count);
        }
        deflater.end();
        return out.toByteArray();
    }
}
