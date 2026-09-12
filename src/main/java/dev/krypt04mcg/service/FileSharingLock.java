package dev.krypt04mcg.service;

import dev.krypt04mcg.util.SecureFiles;
import java.io.IOException;
import java.nio.file.*;

/** Separates a fail-closed runtime lock from successfully persisted user intent. */
public final class FileSharingLock {
    private final Path marker;
    private boolean locked;
    private boolean persisted;

    public FileSharingLock(Path root) {
        marker = root.resolve("file-sharing.disabled");
        // Unknown accessibility and dangling links must not silently enable sharing.
        locked = !Files.notExists(marker, LinkOption.NOFOLLOW_LINKS);
        persisted = Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS);
    }

    public boolean locked() { return locked; }
    public boolean persisted() { return persisted; }

    public void disable() throws IOException {
        locked = true;
        if (!persisted) {
            SecureFiles.atomicWrite(marker, new byte[]{1});
            persisted = true;
        }
    }
}
