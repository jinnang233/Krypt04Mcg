package dev.krypt04mcg.crypto;

import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CryptoEnvelopeKatTest {
    private static CryptoService crypto;
    private static LocalKeyMaterial alice;
    private static LocalKeyMaterial bob;

    /**
     * Provides the keys fixture operation used by the crypto envelope kat test regression scenarios.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @BeforeAll
    static void keys() throws Exception {
        crypto = new CryptoService();
        alice = crypto.generateLocalKeys("alice", "alice-uuid");
        bob = crypto.generateLocalKeys("bob", "bob-uuid");
    }

    /**
     * Verifies that gcm ciphertext contains appended tag and round trips.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void gcmCiphertextContainsAppendedTagAndRoundTrips() throws Exception {
        String plaintext = "known envelope plaintext";

        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", plaintext, true, false);

        assertEquals(plaintext.length() + 16, packet.ciphertext().length);
        assertEquals(plaintext, crypto.decrypt(packet, bob, publicIdentity(alice)));
    }

    /**
     * Verifies that modified tag fails decryption.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void modifiedTagFailsDecryption() throws Exception {
        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "tag kat", true, false);
        byte[] changed = packet.ciphertext().clone();
        changed[changed.length - 1] ^= 0x01;

        assertThrows(CryptoException.class, () -> crypto.decrypt(replaceCiphertext(packet, changed), bob, publicIdentity(alice)));
    }

    /**
     * Verifies that modified authenticated timestamp fails decryption.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void modifiedAuthenticatedTimestampFailsDecryption() throws Exception {
        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "aad kat", true, false);
        EncryptedPacket changedAad = new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(),
                packet.sender(), packet.receiver(), packet.timestampMillis() + 1, packet.messageId(),
                packet.aadFragmentIndex(), packet.aadFragmentTotal(), packet.algorithms(),
                packet.nonce(), packet.kemCiphertext(), packet.ciphertext(), packet.signature());

        assertThrows(CryptoException.class, () -> crypto.decrypt(changedAad, bob, publicIdentity(alice)));
    }

    /**
     * Verifies that modified ciphertext fails decryption.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void modifiedCiphertextFailsDecryption() throws Exception {
        EncryptedPacket packet = crypto.encryptFor(publicIdentity(bob), alice, "alice", "ciphertext kat", true, false);
        byte[] changed = packet.ciphertext().clone();
        changed[0] ^= 0x01;

        assertThrows(CryptoException.class, () -> crypto.decrypt(replaceCiphertext(packet, changed), bob, publicIdentity(alice)));
    }

    /**
     * Verifies that key export import round trip keeps fingerprints.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void keyExportImportRoundTripKeepsFingerprints() throws Exception {
        PublicIdentity identity = publicIdentity(alice);

        assertEquals(alice.kemPublicKey().fingerprint(), identity.kemPublicKey().fingerprint());
        assertEquals(alice.signaturePublicKey().fingerprint(), identity.signaturePublicKey().fingerprint());
        assertTrue(alice.kemPublicKey().keyData().length() > 0);
        assertTrue(alice.signaturePublicKey().keyData().length() > 0);
    }

    /**
     * Provides the replace ciphertext fixture operation used by the crypto envelope kat test regression
     * scenarios.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @return the result described above
     */
    private static EncryptedPacket replaceCiphertext(EncryptedPacket packet, byte[] ciphertext) {
        return new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(), packet.sender(),
                packet.receiver(), packet.timestampMillis(), packet.messageId(), packet.aadFragmentIndex(),
                packet.aadFragmentTotal(), packet.algorithms(), packet.nonce(), packet.kemCiphertext(), ciphertext,
                packet.signature());
    }

    /**
     * Provides the public identity fixture operation used by the crypto envelope kat test regression
     * scenarios.
     *
     * @param material the material supplied to this operation
     * @return the result described above
     */
    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }
}
