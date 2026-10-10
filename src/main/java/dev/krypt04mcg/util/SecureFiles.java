package dev.krypt04mcg.util;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public final class SecureFiles {
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private SecureFiles() {
    }

    /**
     * Rejects linked/special path components, creates the requested directory tree and applies owner-only
     * permissions to the destination. Permission support is required rather than ignored; path checks
     * remain separate from the filesystem mutation.
     *
     * @param directory the directory supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public static void createPrivateDirectories(Path directory) throws IOException {
        rejectLinks(directory);
        Files.createDirectories(directory);
        restrictToOwner(directory, true);
    }

    /**
     * Writes bytes to a private temporary file beside the destination and replaces the destination
     * atomically when supported. The durable overload forces the temporary file and refuses non-atomic
     * fallback; ordinary writes may use replacement fallback. Temporary files are deleted in finally, and
     * final permissions are restricted. No parent-directory fsync guarantee is claimed.
     *
     * @param path the filesystem path used by this operation
     * @param data the data supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public static void atomicWrite(Path path, byte[] data) throws IOException {
        atomicWrite(path, data, false);
    }

    /**
     * Requests forced temporary-file persistence and atomic destination replacement for security journals.
     * If the filesystem cannot perform atomic replacement, the operation fails instead of falling back to
     * a partially replaceable journal.
     *
     * @param path the filesystem path used by this operation
     * @param data the data supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public static void atomicWriteDurable(Path path, byte[] data) throws IOException {
        atomicWrite(path, data, true);
    }

    /**
     * Writes bytes to a private temporary file beside the destination and replaces the destination
     * atomically when supported. The durable overload forces the temporary file and refuses non-atomic
     * fallback; ordinary writes may use replacement fallback. Temporary files are deleted in finally, and
     * final permissions are restricted. No parent-directory fsync guarantee is claimed.
     *
     * @param path the filesystem path used by this operation
     * @param data the data supplied to this operation
     * @param durable whether journal writes require forced persistence and atomic replacement
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void atomicWrite(Path path, byte[] data, boolean durable) throws IOException {
        rejectLinks(path);
        createPrivateDirectories(path.getParent());
        Path temporary = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
        try {
            restrictToOwner(temporary, false);
            try (FileChannel file = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) file.write(buffer);
                if (durable) file.force(true);
            }
            try {
                /*
                 * Replaces the destination through the filesystem move API. Atomic replacement depends on filesystem
                 * support; the surrounding catch path determines whether fallback is allowed. Link/permission
                 * preflight checks are separate and do not eliminate every concurrent path race.
                 */
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                if (durable) throw e;
                /*
                 * Replaces the destination through the filesystem move API. Atomic replacement depends on filesystem
                 * support; the surrounding catch path determines whether fallback is allowed. Link/permission
                 * preflight checks are separate and do not eliminate every concurrent path race.
                 */
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
            restrictToOwner(path, false);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /**
     * Applies owner-read/write POSIX file permissions (plus execute for directories), or an owner-only ACL
     * where supported. Unsupported permission mechanisms raise IOException; permissions are not silently
     * broadened. The helper does not make the owner account itself untrusted-proof.
     *
     * @param path the filesystem path used by this operation
     * @param directory the directory supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public static void restrictToOwner(Path path, boolean directory) throws IOException {
        rejectLinks(path);
        /*
         * Checks the filesystem permission interface before applying owner-only access. POSIX permissions or
         * ACL support must be present; the surrounding implementation rejects unsupported protection instead
         * of assuming private defaults.
         */
        PosixFileAttributeView posix = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (posix != null) {
            Files.setPosixFilePermissions(path, directory ? DIRECTORY_PERMISSIONS : FILE_PERMISSIONS);
            return;
        }
        /*
         * Checks the filesystem permission interface before applying owner-only access. POSIX permissions or
         * ACL support must be present; the surrounding implementation rejects unsupported protection instead
         * of assuming private defaults.
         */
        AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (acl != null) {
            AclEntry ownerOnly = AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(Files.getOwner(path))
                    .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                    .build();
            acl.setAcl(List.of(ownerOnly));
            return;
        }
        throw new IOException("Owner-only permissions are unavailable for " + path);
    }

    // A link in the middle of a path also redirects storage.
    /**
     * Walks the normalized path and all parents using NOFOLLOW_LINKS attributes and rejects symbolic links
     * or special paths. Missing components may later be created after existing parents are checked. These
     * preflight checks do not eliminate every concurrent path-replacement race.
     *
     * @param path the filesystem path used by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public static void rejectLinks(Path path) throws IOException {
        for (Path current = path.toAbsolutePath().normalize(); current != null; current = current.getParent()) {
            try {
                /*
                 * Reads path attributes without following the final symbolic link so the caller can reject linked or
                 * special components. Ancestors are checked by the surrounding loop; this is preflight inspection, not
                 * an atomic directory-handle capability.
                 */
                BasicFileAttributes attributes = Files.readAttributes(current, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                if (attributes.isSymbolicLink() || attributes.isOther()) {
                    throw new IOException("Linked or special storage path is not allowed: " + current);
                }
            } catch (NoSuchFileException ignored) {
                // Missing components may be created after their existing parents are checked.
            }
        }
    }
}
