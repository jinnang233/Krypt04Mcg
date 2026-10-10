package dev.krypt04mcg.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

final class SensitiveFileStoreTest {
    @TempDir Path temp;

    /**
     * Verifies that authenticates content and relative path.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void authenticatesContentAndRelativePath() throws Exception {
        SensitiveFileStore store = new SensitiveFileStore(temp);
        Path original = temp.resolve("original.json");
        store.writeString(original, "secret");
        assertEquals("secret", new SensitiveFileStore(temp).readString(original));
        Path copied = temp.resolve("copied.json");
        Files.copy(original, copied);
        assertThrows(IOException.class, () -> store.readString(copied));
        byte[] bytes = Files.readAllBytes(original);
        bytes[bytes.length - 1] ^= 1;
        Files.write(original, bytes);
        assertThrows(IOException.class, () -> store.readString(original));
    }

    /**
     * Verifies that missing master key does not create a replacement.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void missingMasterKeyDoesNotCreateAReplacement() throws Exception {
        Path file = temp.resolve("secret.json");
        SensitiveFileStore store = new SensitiveFileStore(temp);
        store.writeString(file, "secret");
        Path key = temp.resolve("secrets/master.key");
        byte[] original = Files.readAllBytes(key);
        Files.delete(key);
        assertThrows(IOException.class, () -> new SensitiveFileStore(temp).readString(file));
        assertThrows(IOException.class, () -> store.writeString(file, "changed"));
        assertThrows(IOException.class, () -> new SensitiveFileStore(temp).writeString(file, "changed"));
        assertFalse(Files.exists(key));
        Files.write(key, original);
        assertEquals("secret", new SensitiveFileStore(temp).readString(file));
    }

    /**
     * Verifies that plaintext compatibility cannot escape root.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void plaintextCompatibilityCannotEscapeRoot() throws Exception {
        Path root = temp.resolve("account");
        Path outside = temp.resolve("outside.json");
        Files.writeString(outside, "{}");
        SensitiveFileStore store = new SensitiveFileStore(root);
        assertThrows(IOException.class, () -> store.readString(outside));
        assertThrows(IOException.class, () -> store.writeString(outside, "changed"));
        assertEquals("{}", Files.readString(outside));
        assertFalse(Files.exists(root));
    }

    /**
     * Verifies that missing master key cannot be replaced by writing a new file.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void missingMasterKeyCannotBeReplacedByWritingANewFile() throws Exception {
        Path existing = temp.resolve("sessions/old.json");
        new SensitiveFileStore(temp).writeString(existing, "old secret");
        Path key = temp.resolve("secrets/master.key");
        byte[] originalKey = Files.readAllBytes(key);
        byte[] originalFile = Files.readAllBytes(existing);
        Files.delete(key);
        Path next = temp.resolve("cache/new.json");
        assertThrows(IOException.class, () -> new SensitiveFileStore(temp).writeString(next, "new secret"));
        assertFalse(Files.exists(key));
        assertFalse(Files.exists(next));
        assertArrayEquals(originalFile, Files.readAllBytes(existing));
        Files.write(key, originalKey);
        assertEquals("old secret", new SensitiveFileStore(temp).readString(existing));
    }

    /**
     * Verifies that concurrent stores use one persistent master key.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void concurrentStoresUseOnePersistentMasterKey() throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(8)) {
            ArrayList<Future<?>> writes = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                Path file = temp.resolve(i + ".json");
                writes.add(executor.submit(() -> {
                    start.await();
                    new SensitiveFileStore(temp).writeString(file, "secret");
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> write : writes) {
                write.get();
            }
        }
        for (int i = 0; i < 8; i++) {
            assertEquals("secret", new SensitiveFileStore(temp).readString(temp.resolve(i + ".json")));
        }
    }

    /**
     * Verifies that rejects linked storage directories.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void rejectsLinkedStorageDirectories() throws Exception {
        Path outside = Files.createDirectory(temp.resolve("outside"));
        Path link = temp.resolve("link");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "Symbolic links unavailable: " + e.getMessage());
        }
        assertThrows(IOException.class, () -> new SensitiveFileStore(link).writeString(link.resolve("key"), "secret"));
        assertFalse(Files.exists(outside.resolve("secrets")));
        assertFalse(Files.exists(outside.resolve("key")));
    }
}
