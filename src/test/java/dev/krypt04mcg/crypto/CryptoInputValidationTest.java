package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.*;

final class CryptoInputValidationTest {
    private static final String SESSION_ID = "AAAAAAAAAAAAAAAAAAAAAA";
    private static final byte[] SECRET = new byte[32];

    @ParameterizedTest
    @EnumSource(AeadAlgorithm.class)
    void authenticatedMalformedUtf8IsRejected(AeadAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        for (boolean compressed : new boolean[] {false, true}) {
            var template = crypto.encryptWithSession("bob", "alice", SECRET, SESSION_ID, 0,
                    "", compressed, algorithm);
            byte[] malformed = {(byte) 0xC3, 0x28};
            if (compressed) {
                Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
                try {
                    deflater.setInput(malformed);
                    deflater.finish();
                    byte[] buffer = new byte[64];
                    int count = deflater.deflate(buffer);
                    assertTrue(deflater.finished());
                    malformed = java.util.Arrays.copyOf(buffer, count);
                } finally {
                    deflater.end();
                }
            }
            Cipher cipher = Cipher.getInstance(algorithm == AeadAlgorithm.AES_256_GCM
                    ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
            byte[] key = crypto.deriveSessionSecret(SECRET, template.messageId());
            if (algorithm == AeadAlgorithm.AES_256_GCM) {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(128, template.nonce()));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"),
                        new IvParameterSpec(template.nonce()));
            }
            cipher.updateAAD(new PacketCodec().aadFor(template));
            var packet = withCiphertext(template, cipher.doFinal(malformed));
            assertThrows(CryptoException.class, () -> crypto.decryptWithSession(packet,
                    "bob", "alice", SECRET, SESSION_ID, 0));
        }
    }

    @Test
    void malformedJavaStringsAreNotSilentlyReplaced() {
        CryptoService crypto = new CryptoService();
        for (String message : new String[] {null, String.valueOf((char) 0xD800), String.valueOf((char) 0xDC00)}) {
            assertThrows(CryptoException.class, () -> crypto.encryptWithSession("bob", "alice", SECRET,
                    SESSION_ID, 0, message, false, AeadAlgorithm.AES_256_GCM));
        }
    }

    @Test
    void rejectsOversizedMessagesBeforeUsingRandomness() {
        SecureRandom mustNotBeUsed = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                fail("Oversized plaintext must be rejected before cryptographic operations");
            }
        };
        CryptoService crypto = new CryptoService(mustNotBeUsed, new PacketCodec());
        assertThrows(CryptoException.class, () -> crypto.encryptWithSession("bob", "alice", SECRET,
                SESSION_ID, 0, "a".repeat(CryptoService.MAX_PLAINTEXT_BYTES + 1), true,
                AeadAlgorithm.AES_256_GCM));
    }

    @Test
    void oversizedCiphertextIsRejectedBeforeAuthenticationOrKeyAccess() throws Exception {
        CryptoService crypto = new CryptoService(1024);
        for (boolean compressed : new boolean[] {false, true}) {
            var template = crypto.encryptWithSession("bob", "alice", SECRET, SESSION_ID, 0,
                    "", compressed, AeadAlgorithm.AES_256_GCM);
            var packet = withCiphertext(template, new byte[100_000]);
            CryptoException exception = assertThrows(CryptoException.class, () -> crypto.decryptWithSession(
                    packet, "bob", "alice", SECRET, SESSION_ID, 0));
            assertTrue(exception.getMessage().contains("Ciphertext"));
            assertThrows(CryptoException.class, () -> crypto.decrypt(packet, null, null));
        }
    }

    @Test
    void unsignedEncryptionDoesNotRequireSigningKeys() throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("bob", "uuid", KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);
        var identity = new PublicIdentity("bob", "uuid", keys.kemPublicKey(), keys.signaturePublicKey());
        var packet = crypto.encryptFor(identity, null, "alice", "hello", false);
        assertEquals("hello", crypto.decrypt(packet, keys, null));
        assertThrows(CryptoException.class, () -> crypto.encryptFor(identity, null, "alice", "hello", true));
    }

    @ParameterizedTest
    @EnumSource(AeadAlgorithm.class)
    void validUnicodeAtByteLimitRoundTrips(AeadAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService(7);
        String message = "汉" + new String(Character.toChars(0x1F642));
        for (boolean compressed : new boolean[] {false, true}) {
            var packet = crypto.encryptWithSession("bob", "alice", SECRET, SESSION_ID, 0, message, compressed, algorithm);
            assertEquals(message, crypto.decryptWithSession(packet, "bob", "alice", SECRET, SESSION_ID, 0));
            assertThrows(CryptoException.class, () -> crypto.encryptWithSession("bob", "alice", SECRET,
                    SESSION_ID, 0, message + "a", compressed, algorithm));
        }
    }

    private static EncryptedPacket withCiphertext(EncryptedPacket p, byte[] ciphertext) {
        return new EncryptedPacket(p.protocolVersion(), p.type(), p.flags(), p.sender(), p.receiver(),
                p.timestampMillis(), p.messageId(), p.aadFragmentIndex(), p.aadFragmentTotal(), p.algorithms(),
                p.nonce(), p.kemCiphertext(), ciphertext, p.signature(), p.sessionId(), p.sequence());
    }
}
