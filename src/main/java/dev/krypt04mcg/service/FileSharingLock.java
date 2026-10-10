package dev.krypt04mcg.service;

import dev.krypt04mcg.util.SecureFiles;
import java.io.IOException;
import java.nio.file.*;

/** Separates a fail-closed runtime lock from successfully persisted user intent. */
public final class FileSharingLock {
    private final Path marker;
    private boolean locked;
    private boolean persisted;

    /**
     * Creates a file sharing lock with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public FileSharingLock(Path root) {
        marker = root.resolve("file-sharing.disabled");
        // Unknown accessibility and dangling links must not silently enable sharing.
        locked = !Files.notExists(marker, LinkOption.NOFOLLOW_LINKS);
        persisted = Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS);
    }

    /**
     * Returns the recorded locked for the persistent file-sharing disable state.
     *
     * @return whether the condition or operation described above succeeds
     */
    public boolean locked() { return locked; }
    /**
     * Returns the recorded persisted for the persistent file-sharing disable state.
     *
     * @return whether the condition or operation described above succeeds
     */
    public boolean persisted() { return persisted; }

    /**
     * Performs the disable operation for the persistent file-sharing disable state.
     *
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public void disable() throws IOException {
        locked = true;
        if (!persisted) {
            SecureFiles.atomicWrite(marker, new byte[]{1});
            persisted = true;
        }
    }
}
