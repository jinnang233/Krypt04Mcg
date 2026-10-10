package dev.krypt04mcg.service;

import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.util.SensitiveFileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class KeyTrustServiceTest {
    @TempDir
    private Path tempDir;

    /**
     * Verifies that verification requires and binds both fingerprints.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void verificationRequiresAndBindsBothFingerprints() throws Exception {
        CryptoService crypto = new CryptoService();
        PublicIdentity bob = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid"));
        PublicIdentity replaced = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid"));
        KeyTrustService trust = new KeyTrustService(tempDir);

        assertFalse(trust.fingerprintMatches(bob, bob.kemPublicKey().fingerprint()));
        assertFalse(trust.fingerprintMatches(bob, bob.signaturePublicKey().fingerprint()));
        assertTrue(trust.fingerprintMatches(bob, KeyTrustService.fingerprintPair(bob)));

        trust.markVerified("bob", bob);
        assertEquals(TrustState.VERIFIED, trust.trustState("bob", bob));
        trust.rememberTofu("bob", bob);
        assertEquals(TrustState.VERIFIED, trust.trustState("bob", bob));
        assertEquals(TrustState.DISTRUSTED, trust.trustState("bob", replaced));
        assertTrue(SensitiveFileStore.isEncrypted(tempDir.resolve("keys").resolve("trust.json")));
    }

    /**
     * Verifies that corrupted trust entries do not fall back to tofu.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void corruptedTrustEntriesDoNotFallBackToTofu() throws Exception {
        Path file = tempDir.resolve("keys/trust.json");
        for (String entry : java.util.List.of("null", "{}", "{\"state\":\"UNKNOWN\"}",
                "{\"state\":\"VERIFIED\",\"kemFingerprint\":\"partial\"}")) {
            new SensitiveFileStore(tempDir).writeString(file, "{\"bob\":" + entry + "}");
            org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
                    () -> new KeyTrustService(tempDir).trustState("bob", null));
        }
    }

    /**
     * Verifies that forgetting peer persists and replacement starts with tofu trust.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void forgettingPeerPersistsAndReplacementStartsWithTofuTrust() throws Exception {
        CryptoService crypto = new CryptoService();
        PublicIdentity bob = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid",
                dev.krypt04mcg.config.KemAlgorithm.ML_KEM_768,
                dev.krypt04mcg.config.SignatureAlgorithm.ML_DSA_44));
        KeyTrustService trust = new KeyTrustService(tempDir);
        trust.markVerified("bob", bob);
        trust.markDistrusted("carol", null);
        trust.forget("BoB");
        trust = new KeyTrustService(tempDir);
        assertEquals(TrustState.UNTRUSTED, trust.trustState("bob", null));
        assertEquals(TrustState.DISTRUSTED, trust.trustState("carol", null));
        trust.forget("bob");
        PublicIdentity replacement = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid",
                dev.krypt04mcg.config.KemAlgorithm.ML_KEM_768,
                dev.krypt04mcg.config.SignatureAlgorithm.ML_DSA_44));
        trust.rememberTofu("bob", replacement);
        assertEquals(TrustState.TOFU_TRUSTED, trust.trustState("bob", replacement));
    }

    /**
     * Provides the public identity fixture operation used by the key trust service test regression
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
