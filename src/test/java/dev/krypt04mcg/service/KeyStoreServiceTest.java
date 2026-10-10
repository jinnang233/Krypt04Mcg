package dev.krypt04mcg.service;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

final class KeyStoreServiceTest {
    @TempDir
    private Path tempDir;

    /**
     * Verifies that generates and reloads local keys.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void generatesAndReloadsLocalKeys() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService first = new KeyStoreService(tempDir, cryptoService);
        first.init("alice", "alice-uuid");
        assertEquals("ML-KEM-768+X25519/public", first.local().kemPublicKey().algorithm());
        assertEquals("MLDSA65-Ed25519-SHA512/public", first.local().signaturePublicKey().algorithm());

        Path localKeys = tempDir.resolve("keys").resolve("private").resolve("local.json");
        Path publicKeys = tempDir.resolve("keys").resolve("public").resolve("self-public.json");
        Path exportedPublicKeys = tempDir.resolve("export").resolve("self-public.json");
        assertTrue(Files.exists(localKeys));
        assertTrue(Files.exists(publicKeys));
        assertTrue(Files.exists(exportedPublicKeys));
        assertTrue(SensitiveFileStore.isEncrypted(localKeys));
        assertFalse(new String(Files.readAllBytes(localKeys), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains("keyData"));

        KeyStoreService second = new KeyStoreService(tempDir, cryptoService);
        second.init("alice", "alice-uuid");

        assertEquals(first.local().kemPublicKey().fingerprint(), second.local().kemPublicKey().fingerprint());
        assertEquals(first.local().signaturePublicKey().fingerprint(), second.local().signaturePublicKey().fingerprint());
    }

    /**
     * Verifies that config changes do not replace existing keys until fingerprint confirmed regeneration.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void configChangesDoNotReplaceExistingKeysUntilFingerprintConfirmedRegeneration() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService first = new KeyStoreService(tempDir, cryptoService);
        // Existing non-hybrid keys must survive a change to hybrid defaults/configuration.
        first.init("alice", "alice-uuid", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_512);
        String originalFingerprint = first.regenerationFingerprint();

        KeyStoreService reloaded = new KeyStoreService(tempDir, cryptoService);
        reloaded.init("alice", "alice-uuid", KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);

        assertEquals(originalFingerprint, reloaded.regenerationFingerprint());
        assertEquals("ML-KEM-768/public", reloaded.local().kemPublicKey().algorithm());
        assertEquals("Falcon-512/public", reloaded.local().signaturePublicKey().algorithm());
        assertThrows(CryptoException.class, () -> reloaded.regenerate("wrong-fingerprint",
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44));

        LocalKeyMaterial regenerated = reloaded.regenerate(originalFingerprint,
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);

        assertNotEquals(originalFingerprint, regenerated.kemPublicKey().fingerprint());
        assertEquals("ML-KEM-512/public", regenerated.kemPublicKey().algorithm());
        assertEquals("ML-DSA-44/public", regenerated.signaturePublicKey().algorithm());

        KeyStoreService afterRestart = new KeyStoreService(tempDir, cryptoService);
        afterRestart.init("alice", "alice-uuid");
        assertEquals(regenerated.kemPublicKey().fingerprint(), afterRestart.local().kemPublicKey().fingerprint());
        assertEquals("ML-KEM-512/public", afterRestart.local().kemPublicKey().algorithm());
    }

    /**
     * Verifies that exports public identity to export directory.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void exportsPublicIdentityToExportDirectory() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");

        KeyStoreService.PublicKeyExport exported = keyStoreService.exportOwnPublicFile();

        assertEquals(tempDir.resolve("export").resolve("self-public.json").toAbsolutePath().normalize(), exported.path());
        assertTrue(Files.exists(exported.path()));
        PublicIdentity exportedIdentity = JsonSupport.prettyGson()
                .fromJson(Files.readString(exported.path()), PublicIdentity.class);
        assertEquals(keyStoreService.local().kemPublicKey().fingerprint(),
                exportedIdentity.kemPublicKey().fingerprint());
        assertEquals(keyStoreService.local().signaturePublicKey().fingerprint(),
                exportedIdentity.signaturePublicKey().fingerprint());
        assertEquals(exportedIdentity.kemPublicKey().fingerprint(), exported.identity().kemPublicKey().fingerprint());
    }

    /**
     * Verifies that finds public identity by owner when filename differs.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void findsPublicIdentityByOwnerWhenFilenameDiffers() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        LocalKeyMaterial peerKeys = cryptoService.generateLocalKeys("casey", "casey-uuid");
        PublicIdentity peer = publicIdentity(peerKeys);

        Path publicDir = tempDir.resolve("keys").resolve("public");
        Files.writeString(publicDir.resolve("casey-public.json"), JsonSupport.prettyGson().toJson(peer));

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.kemPublicKey().fingerprint(), found.kemPublicKey().fingerprint());
    }

    /**
     * Verifies that imports public identity from config relative file.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void importsPublicIdentityFromConfigRelativeFile() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        LocalKeyMaterial peerKeys = cryptoService.generateLocalKeys("casey", "casey-uuid");
        PublicIdentity peer = publicIdentity(peerKeys);

        Files.writeString(tempDir.resolve("casey.json"), JsonSupport.prettyGson().toJson(peer));
        keyStoreService.importPublicIdentity("casey", "casey.json");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    /**
     * Verifies that imports public identity from quoted config relative file.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void importsPublicIdentityFromQuotedConfigRelativeFile() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        LocalKeyMaterial peerKeys = cryptoService.generateLocalKeys("casey", "casey-uuid");
        PublicIdentity peer = publicIdentity(peerKeys);

        Files.writeString(tempDir.resolve("casey quoted.json"), JsonSupport.prettyGson().toJson(peer));
        keyStoreService.importPublicIdentity("casey", "\"casey quoted.json\"");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    /**
     * Verifies that imports from legacy config root after account isolation.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void importsFromLegacyConfigRootAfterAccountIsolation() throws Exception {
        CryptoService cryptoService = new CryptoService();
        Path baseRoot = tempDir.resolve("config").resolve("krypt04mcg");
        Path accountRoot = baseRoot.resolve("accounts").resolve("alice-uuid");
        KeyStoreService keyStoreService = new KeyStoreService(accountRoot, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        PublicIdentity peer = publicIdentity(cryptoService.generateLocalKeys("casey", "casey-uuid"));
        Path importFile = baseRoot.resolve("incoming").resolve("casey.json");
        Files.createDirectories(importFile.getParent());
        Files.writeString(importFile, JsonSupport.prettyGson().toJson(peer));

        keyStoreService.importPublicIdentity("casey", "incoming/casey.json");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    /**
     * Verifies that imports from game relative path after account isolation.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void importsFromGameRelativePathAfterAccountIsolation() throws Exception {
        CryptoService cryptoService = new CryptoService();
        Path baseRoot = tempDir.resolve("config").resolve("krypt04mcg");
        Path accountRoot = baseRoot.resolve("accounts").resolve("alice-uuid");
        KeyStoreService keyStoreService = new KeyStoreService(accountRoot, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        PublicIdentity peer = publicIdentity(cryptoService.generateLocalKeys("casey", "casey-uuid"));
        Path importFile = baseRoot.resolve("incoming").resolve("casey.json");
        Files.createDirectories(importFile.getParent());
        Files.writeString(importFile, JsonSupport.prettyGson().toJson(peer));

        keyStoreService.importPublicIdentity("casey", "config/krypt04mcg/incoming/casey.json");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    /**
     * Verifies that imports from quoted absolute windows path.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void importsFromQuotedAbsoluteWindowsPath() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir.resolve("account"), cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        PublicIdentity peer = publicIdentity(cryptoService.generateLocalKeys("casey", "casey-uuid"));
        Path importFile = tempDir.resolve("casey public.json").toAbsolutePath();
        Files.writeString(importFile, JsonSupport.prettyGson().toJson(peer));

        keyStoreService.importPublicIdentity("casey", "\"" + importFile + "\"");

        PublicIdentity found = keyStoreService.findPublicIdentity("casey").orElseThrow();
        assertEquals(peer.signaturePublicKey().fingerprint(), found.signaturePublicKey().fingerprint());
    }

    /**
     * Verifies that reports missing import file as a file error.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void reportsMissingImportFileAsAFileError() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");

        Exception error = assertThrows(Exception.class,
                () -> keyStoreService.importPublicIdentity("casey", "missing/casey.json"));

        assertTrue(error.getMessage().contains("Import file was not found or is not readable"));
    }

    /**
     * Verifies that rejects config relative import path traversal.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void rejectsConfigRelativeImportPathTraversal() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        Path outside = Files.createTempFile("krypt04mcg-outside-", ".json");
        try {
            Files.writeString(outside, "{}");
            String traversal = tempDir.relativize(outside).toString();

            assertThrows(Exception.class, () -> keyStoreService.importPublicIdentity("casey", traversal));
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    /**
     * Verifies that recomputes imported fingerprints from decoded public keys.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void recomputesImportedFingerprintsFromDecodedPublicKeys() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        PublicIdentity peer = publicIdentity(cryptoService.generateLocalKeys("bob", "bob-uuid"));
        KeyRecord forgedKem = new KeyRecord(peer.kemPublicKey().algorithm(), peer.kemPublicKey().owner(),
                peer.kemPublicKey().uuid(), "00".repeat(32), peer.kemPublicKey().createdAt(),
                peer.kemPublicKey().keyData());
        PublicIdentity forged = new PublicIdentity(peer.owner(), peer.uuid(), forgedKem, peer.signaturePublicKey());

        PublicIdentity imported = keyStoreService.importPublicIdentity("bob",
                JsonSupport.prettyGson().toJson(forged));

        assertEquals(peer.kemPublicKey().fingerprint(), imported.kemPublicKey().fingerprint());
        assertNotEquals(forgedKem.fingerprint(), imported.kemPublicKey().fingerprint());
        assertEquals(64, imported.kemPublicKey().fingerprint().length());
        assertThrows(java.io.IOException.class, () -> keyStoreService.importPublicIdentity("bob",
                JsonSupport.prettyGson().toJson(peer).replace("bob-uuid", "another-uuid")));
    }

    /**
     * Verifies that rejects inner identity and public role mismatches.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void rejectsInnerIdentityAndPublicRoleMismatches() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService keyStoreService = new KeyStoreService(tempDir, cryptoService);
        keyStoreService.init("alice", "alice-uuid");
        PublicIdentity peer = publicIdentity(cryptoService.generateLocalKeys("bob", "bob-uuid"));
        KeyRecord wrongOwner = new KeyRecord(peer.kemPublicKey().algorithm(), "mallory", peer.uuid(),
                peer.kemPublicKey().fingerprint(), peer.kemPublicKey().createdAt(), peer.kemPublicKey().keyData());
        PublicIdentity ownerMismatch = new PublicIdentity(peer.owner(), peer.uuid(), wrongOwner,
                peer.signaturePublicKey());
        KeyRecord wrongRole = new KeyRecord(peer.kemPublicKey().algorithm().replace("/public", "/private"),
                peer.owner(), peer.uuid(), peer.kemPublicKey().fingerprint(), peer.kemPublicKey().createdAt(),
                peer.kemPublicKey().keyData());
        PublicIdentity roleMismatch = new PublicIdentity(peer.owner(), peer.uuid(), wrongRole,
                peer.signaturePublicKey());

        assertThrows(Exception.class, () -> keyStoreService.importPublicIdentity("bob",
                JsonSupport.prettyGson().toJson(ownerMismatch)));
        assertThrows(Exception.class, () -> keyStoreService.importPublicIdentity("bob",
                JsonSupport.prettyGson().toJson(roleMismatch)));
    }

    /**
     * Verifies that filename cannot substitute another players identity.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void filenameCannotSubstituteAnotherPlayersIdentity() throws Exception {
        CryptoService crypto = new CryptoService();
        KeyStoreService store = new KeyStoreService(tempDir, crypto);
        PublicIdentity mallory = publicIdentity(crypto.generateLocalKeys("mallory", "mallory-uuid",
                dev.krypt04mcg.config.KemAlgorithm.ML_KEM_768,
                dev.krypt04mcg.config.SignatureAlgorithm.ML_DSA_44));
        Path publicDir = Files.createDirectories(tempDir.resolve("keys/public"));
        Files.writeString(publicDir.resolve("alice.json"), JsonSupport.prettyGson().toJson(mallory));
        assertThrows(java.io.IOException.class, () -> store.findPublicIdentity("alice"));
    }

    /**
     * Verifies that removes all peer records and allows replacement without changing own keys.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void removesAllPeerRecordsAndAllowsReplacementWithoutChangingOwnKeys() throws Exception {
        CryptoService crypto = new CryptoService();
        KeyStoreService store = new KeyStoreService(tempDir, crypto);
        store.init("alice", "alice-uuid", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        PublicIdentity own = store.ownPublicIdentity();
        PublicIdentity bob = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44));
        store.importPublicIdentity("bob", JsonSupport.prettyGson().toJson(bob));
        Path legacy = tempDir.resolve("keys/public/legacy-bob.json");
        Files.copy(tempDir.resolve("keys/public/bob.json"), legacy);

        assertTrue(store.removePublicIdentity("BoB"));
        assertFalse(Files.exists(legacy));
        assertTrue(store.findPublicIdentity("bob").isEmpty());
        assertFalse(store.removePublicIdentity("bob"));
        assertFalse(store.removePublicIdentity("../alice"));
        assertFalse(store.removePublicIdentity("self-public"));
        assertThrows(java.io.IOException.class, () -> store.removePublicIdentity("ALICE"));
        assertEquals(own, store.findPublicIdentity("alice").orElseThrow());
        assertEquals(1, store.listPublicIdentities().size());

        PublicIdentity replacement = publicIdentity(crypto.generateLocalKeys("bob", "bob-uuid",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44));
        assertEquals(replacement, store.importPublicIdentity("bob", JsonSupport.prettyGson().toJson(replacement)));
        KeyStoreService reloaded = new KeyStoreService(tempDir, crypto);
        reloaded.init("alice", "alice-uuid");
        assertEquals(own, reloaded.ownPublicIdentity());
        assertEquals(replacement, reloaded.findPublicIdentity("bob").orElseThrow());
    }

    /**
     * Provides the public identity fixture operation used by the key store service test regression
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
