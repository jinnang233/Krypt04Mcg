package dev.krypt04mcg.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class FileSharingLockTest {
    @TempDir Path temp;

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

    @Test void existingMarkerIsNeverOverwritten() throws Exception {
        Files.writeString(temp.resolve("file-sharing.disabled"), "existing");
        var lock = new FileSharingLock(temp);
        lock.disable();
        assertEquals("existing", Files.readString(temp.resolve("file-sharing.disabled")));
        assertTrue(lock.persisted());
    }
}
