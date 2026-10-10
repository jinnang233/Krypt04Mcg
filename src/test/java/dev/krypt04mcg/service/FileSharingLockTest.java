package dev.krypt04mcg.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class FileSharingLockTest {
    @TempDir Path temp;

    /**
     * Verifies that failed write stays locked but can be retried and persisted.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void failedWriteStaysLockedButCanBeRetriedAndPersisted() throws Exception {
        Path root = temp.resolve("account");
        var lock = new FileSharingLock(root);
        Files.writeString(root, "blocks directory creation");
        assertThrows(IOException.class, lock::disable);
        assertTrue(lock.locked());
        assertFalse(lock.persisted());
        Files.delete(root);
        lock.disable();
        assertTrue(lock.persisted());
        assertTrue(new FileSharingLock(root).locked());
    }

    /**
     * Verifies that existing marker is never overwritten.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void existingMarkerIsNeverOverwritten() throws Exception {
        Files.writeString(temp.resolve("file-sharing.disabled"), "existing");
        var lock = new FileSharingLock(temp);
        lock.disable();
        assertEquals("existing", Files.readString(temp.resolve("file-sharing.disabled")));
        assertTrue(lock.persisted());
    }
}
