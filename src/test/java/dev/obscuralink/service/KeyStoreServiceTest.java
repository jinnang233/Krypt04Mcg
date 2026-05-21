package dev.obscuralink.service;

import dev.obscuralink.crypto.CryptoService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class KeyStoreServiceTest {
    @TempDir
    private Path tempDir;

    @Test
    void generatesAndReloadsLocalKeys() throws Exception {
        CryptoService cryptoService = new CryptoService();
        KeyStoreService first = new KeyStoreService(tempDir, cryptoService);
        first.init("alice", "alice-uuid");

        Path localKeys = tempDir.resolve("keys").resolve("private").resolve("local.json");
        Path publicKeys = tempDir.resolve("keys").resolve("public").resolve("self-public.json");
        assertTrue(Files.exists(localKeys));
        assertTrue(Files.exists(publicKeys));

        KeyStoreService second = new KeyStoreService(tempDir, cryptoService);
        second.init("alice", "alice-uuid");

        assertEquals(first.local().kemPublicKey().fingerprint(), second.local().kemPublicKey().fingerprint());
        assertEquals(first.local().signaturePublicKey().fingerprint(), second.local().signaturePublicKey().fingerprint());
    }
}
