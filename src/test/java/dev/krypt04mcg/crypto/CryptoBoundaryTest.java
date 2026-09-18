package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.protocol.PacketCodec;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

final class CryptoBoundaryTest {
    private static final String SESSION_ID = "AAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void compressionRespectsConfiguredLimit() throws Exception {
        CryptoService large = new CryptoService(128 * 1024);
        byte[] secret = new byte[32];
        String message = "A".repeat(100 * 1024);
        var packet = large.encryptWithSession("bob", "alice", secret, SESSION_ID, 0,
                message, true, AeadAlgorithm.AES_256_GCM);
        assertEquals(message, large.decryptWithSession(packet, "bob", "alice", secret, SESSION_ID, 0));
        assertThrows(CryptoException.class, () -> new CryptoService(1024)
                .decryptWithSession(packet, "bob", "alice", secret, SESSION_ID, 0));
    }

    @Test
    void rejectsMissingAndWrongSizedSessionSecrets() {
        CryptoService crypto = new CryptoService();
        for (byte[] secret : new byte[][] {null, new byte[0], new byte[1], new byte[31], new byte[33]}) {
            assertThrows(CryptoException.class, () -> crypto.encryptWithSession("bob", "alice", secret,
                    SESSION_ID, 0, "message", false, AeadAlgorithm.AES_256_GCM));
        }
        assertThrows(CryptoException.class, () -> crypto.deriveSessionSecret(new byte[32], null));
        assertThrows(CryptoException.class, () -> crypto.deriveSessionSecret(new byte[32], new byte[15]));
    }

    @Test
    void operationalApisRejectRelabeledKeys() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial keys = crypto.generateLocalKeys("alice", "uuid", KemAlgorithm.ML_KEM_512,
                SignatureAlgorithm.ML_DSA_44);
        byte[] message = {1, 2, 3};
        byte[] signature = crypto.sign(keys.signaturePrivateKey(), message);
        assertThrows(CryptoException.class, () -> crypto.sign(
                relabel(keys.signaturePrivateKey(), "ML-DSA-87/private"), message));
        assertThrows(CryptoException.class, () -> crypto.verify(
                relabel(keys.signaturePublicKey(), "ML-DSA-87/public"), message, signature));
        PublicIdentity receiver = new PublicIdentity("alice", "uuid",
                relabel(keys.kemPublicKey(), "ML-KEM-1024/public"), keys.signaturePublicKey());
        assertThrows(CryptoException.class, () -> crypto.encryptFor(receiver, keys, "alice", "message", false));
    }

    @Test
    void ephemeralKeyOwnsItsArraysAndReturnsSnapshots() {
        byte[] publicBytes = {1, 2};
        byte[] privateBytes = {3, 4};
        try (var key = new EphemeralKemKeyPair(KemAlgorithm.ML_KEM_768, publicBytes, privateBytes)) {
            Arrays.fill(publicBytes, (byte) 0);
            Arrays.fill(privateBytes, (byte) 0);
            assertArrayEquals(new byte[] {1, 2}, key.publicKey());
            assertArrayEquals(new byte[] {3, 4}, key.privateKey());
            byte[] snapshot = key.privateKey();
            snapshot[0] = 9;
            assertEquals(3, key.privateKey()[0]);
            key.close();
            assertArrayEquals(new byte[] {9, 4}, snapshot);
            assertTrue(key.destroyed());
            assertThrows(IllegalStateException.class, key::privateKey);
        }
    }

    @Test
    void rejectsAuthenticatedCompressedPayloadWithTrailingBytes() throws Exception {
        CryptoService crypto = new CryptoService();
        byte[] secret = new byte[32];
        var template = crypto.encryptWithSession("bob", "alice", secret, SESSION_ID, 0,
                "", true, AeadAlgorithm.AES_256_GCM);
        var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(crypto.deriveSessionSecret(secret, template.messageId()), "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, template.nonce()));
        cipher.updateAAD(new PacketCodec().aadFor(template));
        // A complete empty raw DEFLATE stream followed by an extra byte.
        byte[] ciphertext = cipher.doFinal(new byte[] {3, 0, 42});
        var packet = new EncryptedPacket(template.protocolVersion(), template.type(), template.flags(),
                template.sender(), template.receiver(), template.timestampMillis(), template.messageId(),
                template.aadFragmentIndex(), template.aadFragmentTotal(), template.algorithms(), template.nonce(),
                template.kemCiphertext(), ciphertext, template.signature(), template.sessionId(), template.sequence());
        assertThrows(CryptoException.class,
                () -> crypto.decryptWithSession(packet, "bob", "alice", secret, SESSION_ID, 0));
        assertEquals("", crypto.decryptWithSession(template, "bob", "alice", secret, SESSION_ID, 0));
    }

    @Test
    void missingPacketIsReportedAsCryptoException() {
        assertThrows(CryptoException.class, () -> new CryptoService().decrypt(null, null, null));
    }

    private static KeyRecord relabel(KeyRecord key, String algorithm) {
        return new KeyRecord(algorithm, key.owner(), key.uuid(), key.fingerprint(), key.createdAt(), key.keyData());
    }
}
