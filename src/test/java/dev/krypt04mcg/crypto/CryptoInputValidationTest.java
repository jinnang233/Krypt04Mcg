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

    /**
     * Verifies that authenticated malformed utf8 is rejected.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @ParameterizedTest
    @EnumSource(AeadAlgorithm.class)
    void authenticatedMalformedUtf8IsRejected(AeadAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        for (boolean compressed : new boolean[] {false, true}) {
            var template = crypto.encryptWithSession("bob", "alice", SECRET, SESSION_ID, 0,
                    "", compressed, algorithm);
            byte[] malformed = {(byte) 0xC3, 0x28};
            if (compressed) {
                /*
                 * Uses JDK DEFLATE after plaintext size admission and releases compressor resources in the surrounding
                 * lifecycle. Compression changes visible ciphertext length and is not an authentication or
                 * confidentiality primitive.
                 */
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
            /*
             * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
             * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
             * provider or tag failure.
             */
            Cipher cipher = Cipher.getInstance(algorithm == AeadAlgorithm.AES_256_GCM
                    ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
            byte[] key = crypto.deriveSessionSecret(SECRET, template.messageId());
            if (algorithm == AeadAlgorithm.AES_256_GCM) {
                /*
                 * Supplies the explicit AES-GCM tag length and nonce to JCA. Nonce uniqueness under a key is a caller
                 * responsibility; constructing a parameter object neither generates a nonce nor validates peer
                 * identity.
                 */
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(128, template.nonce()));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"),
                        new IvParameterSpec(template.nonce()));
            }
            /*
             * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
             * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
             * tag.
             */
            cipher.updateAAD(new PacketCodec().aadFor(template));
            /*
             * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
             * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
             * output when finalization fails.
             */
            var packet = withCiphertext(template, cipher.doFinal(malformed));
            assertThrows(CryptoException.class, () -> crypto.decryptWithSession(packet,
                    "bob", "alice", SECRET, SESSION_ID, 0));
        }
    }

    /**
     * Verifies that malformed java strings are not silently replaced.
     */
    @Test
    void malformedJavaStringsAreNotSilentlyReplaced() {
        CryptoService crypto = new CryptoService();
        for (String message : new String[] {null, String.valueOf((char) 0xD800), String.valueOf((char) 0xDC00)}) {
            assertThrows(CryptoException.class, () -> crypto.encryptWithSession("bob", "alice", SECRET,
                    SESSION_ID, 0, message, false, AeadAlgorithm.AES_256_GCM));
        }
    }

    /**
     * Verifies that rejects oversized messages before using randomness.
     */
    @Test
    void rejectsOversizedMessagesBeforeUsingRandomness() {
        SecureRandom mustNotBeUsed = new SecureRandom() {
            /**
             * Provides the next bytes fixture operation used by the crypto input validation test regression
             * scenarios.
             *
             * @param bytes the bytes supplied to this operation
             */
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

    /**
     * Verifies that oversized ciphertext is rejected before authentication or key access.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
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

    /**
     * Verifies that malformed sender cannot be normalized into another authenticated identity.
     */
    @Test
    void malformedSenderCannotBeNormalizedIntoAnotherAuthenticatedIdentity() {
        CryptoService crypto = new CryptoService();
        assertThrows(CryptoException.class, () -> crypto.encryptWithSession("bob", "alice\ud800", SECRET,
                SESSION_ID, 0, "hello", false, AeadAlgorithm.AES_256_GCM));
    }

    /**
     * Verifies that malformed encapsulation is rejected as crypto failure.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @ParameterizedTest
    @EnumSource(value = KemAlgorithm.class, names = {"ML_KEM_768", "CMCE_MCELIECE460896", "HQC_HQC128",
            "NTRULPRIME_NTRULPR653", "SNTRUPRIME_SNTRUP653"})
    void malformedEncapsulationIsRejectedAsCryptoFailure(KemAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("bob", "uuid", algorithm, SignatureAlgorithm.ML_DSA_44);
        var identity = new PublicIdentity("bob", "uuid", keys.kemPublicKey(), keys.signaturePublicKey());
        var p = crypto.encryptFor(identity, null, "alice", "hello", false);
        for (int length : new int[] {0, 1, p.kemCiphertext().length - 1, p.kemCiphertext().length + 1}) {
            var malformed = new EncryptedPacket(p.protocolVersion(), p.type(), p.flags(), p.sender(), p.receiver(),
                    p.timestampMillis(), p.messageId(), p.aadFragmentIndex(), p.aadFragmentTotal(), p.algorithms(),
                    p.nonce(), java.util.Arrays.copyOf(p.kemCiphertext(), length), p.ciphertext(), p.signature());
            assertThrows(CryptoException.class, () -> crypto.decrypt(malformed, keys, null),
                    algorithm + " encapsulation length " + length);
        }
    }

    /**
     * Verifies that unsigned encryption does not require signing keys.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void unsignedEncryptionDoesNotRequireSigningKeys() throws Exception {
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("bob", "uuid", KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);
        var identity = new PublicIdentity("bob", "uuid", keys.kemPublicKey(), keys.signaturePublicKey());
        var packet = crypto.encryptFor(identity, null, "alice", "hello", false);
        assertEquals("hello", crypto.decrypt(packet, keys, null));
        assertThrows(CryptoException.class, () -> crypto.encryptFor(identity, null, "alice", "hello", true));
    }

    /**
     * Verifies that valid unicode at byte limit round trips.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
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

    /**
     * Provides the with ciphertext fixture operation used by the crypto input validation test regression
     * scenarios.
     *
     * @param p the p supplied to this operation
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @return the result described above
     */
    private static EncryptedPacket withCiphertext(EncryptedPacket p, byte[] ciphertext) {
        return new EncryptedPacket(p.protocolVersion(), p.type(), p.flags(), p.sender(), p.receiver(),
                p.timestampMillis(), p.messageId(), p.aadFragmentIndex(), p.aadFragmentTotal(), p.algorithms(),
                p.nonce(), p.kemCiphertext(), ciphertext, p.signature(), p.sessionId(), p.sequence());
    }
}
