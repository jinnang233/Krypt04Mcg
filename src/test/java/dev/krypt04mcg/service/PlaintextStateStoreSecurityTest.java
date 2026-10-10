package dev.krypt04mcg.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PlaintextStateStoreSecurityTest {
    @TempDir Path root;

    /**
     * Verifies that linked state is rejected on read and write without changing target.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void linkedStateIsRejectedOnReadAndWriteWithoutChangingTarget() throws Exception {
        for (Store store : stores()) {
            Path outside = root.resolve(store.file().getFileName() + ".outside");
            Files.writeString(outside, "{}");
            Files.createDirectories(store.file().getParent());
            createLink(store.file(), outside);
            assertThrows(IOException.class, store.read()::run, store.file().toString());
            assertThrows(IOException.class, store.write()::run, store.file().toString());
            assertEquals("{}", Files.readString(outside));
        }
    }

    /**
     * Verifies that dangling links cannot be treated as empty state.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void danglingLinksCannotBeTreatedAsEmptyState() throws Exception {
        for (Store store : stores()) {
            Files.createDirectories(store.file().getParent());
            createLink(store.file(), root.resolve("missing"));
            assertThrows(IOException.class, store.read()::run, store.file().toString());
        }
    }

    /**
     * Verifies that linked parent directories cannot redirect state.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void linkedParentDirectoriesCannotRedirectState() throws Exception {
        Path outside = Files.createDirectory(root.resolve("outside"));
        Path linked = root.resolve("linked");
        createLink(linked, outside);
        for (Store store : stores(linked)) {
            assertThrows(IOException.class, store.read()::run, store.file().toString());
            assertThrows(IOException.class, store.write()::run, store.file().toString());
            assertFalse(Files.exists(outside.resolve(linked.relativize(store.file()))));
        }
    }

    /**
     * Verifies that created state files are private and still round trip.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void createdStateFilesArePrivateAndStillRoundTrip() throws Exception {
        assumeTrue(Files.getFileStore(root).supportsFileAttributeView("posix"));
        for (Store store : stores()) {
            store.write().run();
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(store.file()));
            Files.setPosixFilePermissions(store.file(), Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ));
            store.read().run();
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(store.file()));
        }
        assertEquals(List.of("Bob"), new GroupService(root).find("friends").orElseThrow().members());
        assertEquals("fingerprints", new SentMessageCacheService(root).find("message")
                .orElseThrow().recipientFingerprint());
        assertTrue(new DecryptionHistoryService(root).lastSuccess("Bob").isPresent());
        var history = new DecryptionHistoryService(root);
        assertTrue(history.recordAcceptedPacket("Bob", new byte[16], new byte[12]));
        assertFalse(new DecryptionHistoryService(root).recordAcceptedPacket("Bob", new byte[16], new byte[12]));
    }

    /**
     * Provides the stores fixture operation used by the plaintext state store security test regression
     * scenarios.
     *
     * @return the result described above
     */
    private List<Store> stores() {
        return stores(root);
    }

    /**
     * Provides the stores fixture operation used by the plaintext state store security test regression
     * scenarios.
     *
     * @param directory the directory supplied to this operation
     * @return the result described above
     */
    private List<Store> stores(Path directory) {
        var groups = new GroupService(directory);
        var sent = new SentMessageCacheService(directory);
        var history = new DecryptionHistoryService(directory);
        return List.of(new Store(directory.resolve("groups.json"),
                        () -> groups.create("friends", List.of("Bob")), () -> groups.find("friends")),
                new Store(directory.resolve("cache/sent-fragments.json"),
                        () -> sent.remember("message", "Bob", List.of("fragment"), "fingerprints"), () -> sent.find("message")),
                new Store(directory.resolve("cache/decryption-history.json"),
                        () -> history.recordSuccess("Bob"), () -> history.lastSuccess("Bob")));
    }

    /**
     * Provides the create link fixture operation used by the plaintext state store security test
     * regression scenarios.
     *
     * @param link the link supplied to this operation
     * @param target the target supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void createLink(Path link, Path target) throws IOException {
        try { Files.createSymbolicLink(link, target); }
        catch (UnsupportedOperationException | IOException unavailable) {
            assumeTrue(false, "Symbolic links unavailable: " + unavailable.getMessage());
        }
    }

    @FunctionalInterface private interface IoAction {
        /**
         * Provides the run fixture operation used by the plaintext state store security test regression
         * scenarios.
         *
         * @throws IOException if input/output, stored-state validation or resource handling fails
         */
        void run() throws IOException; }
    private record Store(Path file, IoAction write, IoAction read) {}
}
