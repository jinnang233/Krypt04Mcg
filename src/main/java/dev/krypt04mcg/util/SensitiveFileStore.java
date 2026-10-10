package dev.krypt04mcg.util;

import com.sun.jna.Platform;
import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.platform.win32.WinCrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public final class SensitiveFileStore {
    private static final byte[] FILE_MAGIC = "KMCGSEC1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY_MAGIC = "KMCGKEY1".getBytes(StandardCharsets.US_ASCII);
    private static final byte KEY_DPAPI = 1;
    private static final byte KEY_OWNER_ONLY = 2;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte[] DPAPI_ENTROPY = "Krypt04Mcg local storage v1".getBytes(StandardCharsets.UTF_8);

    private final Path root;
    private final Path masterKeyFile;
    private final SecureRandom random = new SecureRandom();
    private byte[] masterKey;

    /**
     * Creates a sensitive file store with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public SensitiveFileStore(Path root) {
        this.root = root.toAbsolutePath().normalize();
        this.masterKeyFile = this.root.resolve("secrets").resolve("master.key");
    }

    /**
     * Checks the rooted path label and reads a legacy plaintext file or a versioned AES-GCM envelope.
     * Encrypted data authenticates the root-relative path as AAD, so moving an envelope to another logical
     * path fails verification. Authentication failures become IOExceptions; temporary encoded/ciphertext
     * buffers are overwritten. A returned String is immutable and cannot be reliably erased.
     *
     * @param path the filesystem path used by this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized String readString(Path path) throws IOException {
        byte[] aad = label(path);
        byte[] encoded = Files.readAllBytes(path);
        if (!startsWith(encoded, FILE_MAGIC)) {
            String plaintext = new String(encoded, StandardCharsets.UTF_8);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(encoded, (byte) 0);
            return plaintext;
        }
        if (encoded.length < FILE_MAGIC.length + NONCE_BYTES + 16) {
            throw new IOException("Encrypted file is truncated: " + path);
        }
        byte[] nonce = Arrays.copyOfRange(encoded, FILE_MAGIC.length, FILE_MAGIC.length + NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(encoded, FILE_MAGIC.length + NONCE_BYTES, encoded.length);
        try {
            /*
             * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
             * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
             * provider or tag failure.
             */
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            /*
             * Supplies the explicit AES-GCM tag length and nonce to JCA. Nonce uniqueness under a key is a caller
             * responsibility; constructing a parameter object neither generates a nonce nor validates peer
             * identity.
             */
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(masterKey(false), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            /*
             * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
             * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
             * tag.
             */
            cipher.updateAAD(aad);
            /*
             * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
             * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
             * output when finalization fails.
             */
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to decrypt sensitive file " + path, e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(nonce, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(ciphertext, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Encrypts UTF-8 storage contents with AES-256-GCM and a fresh random 96-bit nonce, binding the
     * normalized root-relative path as AAD. The versioned envelope is written through private atomic
     * replacement; the internal overload selects durable journal behavior. Plaintext and nonce buffers are
     * overwritten after the operation.
     *
     * @param path the filesystem path used by this operation
     * @param value the value supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void writeString(Path path, String value) throws IOException {
        writeString(path, value, false);
    }

    /**
     * Writes an authenticated encrypted storage envelope using the durable atomic-replacement path
     * required by handshake/counter journals. Unsupported atomic replacement fails rather than silently
     * accepting a non-atomic journal write.
     *
     * @param path the filesystem path used by this operation
     * @param value the value supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void writeDurableString(Path path, String value) throws IOException {
        writeString(path, value, true);
    }

    /**
     * Encrypts UTF-8 storage contents with AES-256-GCM and a fresh random 96-bit nonce, binding the
     * normalized root-relative path as AAD. The versioned envelope is written through private atomic
     * replacement; the internal overload selects durable journal behavior. Plaintext and nonce buffers are
     * overwritten after the operation.
     *
     * @param path the filesystem path used by this operation
     * @param value the value supplied to this operation
     * @param durable whether journal writes require forced persistence and atomic replacement
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void writeString(Path path, String value, boolean durable) throws IOException {
        byte[] aad = label(path);
        byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[NONCE_BYTES];
        /*
         * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
         * Production randomness must remain unpredictable; a random nonce still depends on avoiding
         * collisions/reuse under its key.
         */
        random.nextBytes(nonce);
        try {
            /*
             * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
             * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
             * provider or tag failure.
             */
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            /*
             * Supplies the explicit AES-GCM tag length and nonce to JCA. Nonce uniqueness under a key is a caller
             * responsibility; constructing a parameter object neither generates a nonce nor validates peer
             * identity.
             */
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey(!isEncrypted(path)), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            /*
             * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
             * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
             * tag.
             */
            cipher.updateAAD(aad);
            /*
             * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
             * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
             * output when finalization fails.
             */
            byte[] ciphertext = cipher.doFinal(plaintext);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(FILE_MAGIC.length + nonce.length + ciphertext.length);
            bytes.write(FILE_MAGIC);
            bytes.write(nonce);
            bytes.write(ciphertext);
            if (durable) SecureFiles.atomicWriteDurable(path, bytes.toByteArray());
            else SecureFiles.atomicWrite(path, bytes.toByteArray());
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(ciphertext, (byte) 0);
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to encrypt sensitive file " + path, e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(plaintext, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(nonce, (byte) 0);
        }
    }

    /**
     * Reports whether encrypted holds for the encrypted account storage.
     *
     * @param path the filesystem path used by this operation
     * @return whether the condition or operation described above succeeds
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public static boolean isEncrypted(Path path) throws IOException {
        if (!Files.isRegularFile(path) || Files.size(path) < FILE_MAGIC.length) {
            return false;
        }
        byte[] prefix = new byte[FILE_MAGIC.length];
        try (var in = Files.newInputStream(path)) {
            return in.read(prefix) == prefix.length && Arrays.equals(prefix, FILE_MAGIC);
        }
    }

    /**
     * Loads or creates the account storage master key under a JVM lock plus a file lock for other game
     * processes. Cached-key or encrypted-file evidence prevents silently generating a replacement key
     * after loss of the original. Path-link checks and private storage permissions remain required.
     *
     * @param create the create supplied to this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private byte[] masterKey(boolean create) throws IOException {
        // The JVM lock avoids overlapping locks; the file lock covers other game processes.
        synchronized (SensitiveFileStore.class) {
            SecureFiles.rejectLinks(masterKeyFile);
            if (!Files.exists(masterKeyFile) && (!create || masterKey != null)) {
                throw new IOException("Local master key is missing; restore it from backup");
            }
            if (masterKey != null) {
                return masterKey;
            }
            SecureFiles.createPrivateDirectories(masterKeyFile.getParent());
            Path lockFile = masterKeyFile.resolveSibling("master.key.lock");
            SecureFiles.rejectLinks(lockFile);
            try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                 var lock = channel.lock()) {
                return loadMasterKey(create);
            }
        }
    }

    /**
     * Checks the key-file magic, protection mode and exact 32-byte unwrapped key size, or initializes a
     * key only when no encrypted account files remain. Windows DPAPI mode requires Windows; owner-only
     * mode stores a protected-by-permissions raw key. Invalid or missing protected material fails closed.
     *
     * @param create the create supplied to this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private byte[] loadMasterKey(boolean create) throws IOException {
        if (!Files.exists(masterKeyFile)) {
            if (!create) {
                throw new IOException("Local master key is missing; restore it from backup");
            }
            // A new destination says nothing about the other files in this account.
            // Check under the master-key lock before initializing a new storage epoch.
            requireUnencryptedStorage();
            byte[] generated = new byte[KEY_BYTES];
            /*
             * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
             * Production randomness must remain unpredictable; a random nonce still depends on avoiding
             * collisions/reuse under its key.
             */
            random.nextBytes(generated);
            try {
                writeMasterKey(generated);
                masterKey = generated;
                return masterKey;
            } catch (IOException e) {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(generated, (byte) 0);
                throw e;
            }
        }
        SecureFiles.restrictToOwner(masterKeyFile, false);
        byte[] stored = Files.readAllBytes(masterKeyFile);
        try {
            if (!startsWith(stored, KEY_MAGIC) || stored.length <= KEY_MAGIC.length + 1) {
                throw new IOException("Invalid local master key file");
            }
            byte mode = stored[KEY_MAGIC.length];
            byte[] protectedKey = Arrays.copyOfRange(stored, KEY_MAGIC.length + 1, stored.length);
            byte[] unwrapped = switch (mode) {
                case KEY_DPAPI -> unprotectWithDpapi(protectedKey);
                case KEY_OWNER_ONLY -> protectedKey;
                default -> throw new IOException("Unsupported local master key protection mode: " + mode);
            };
            if (unwrapped.length != KEY_BYTES) {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(unwrapped, (byte) 0);
                throw new IOException("Invalid local master key length");
            }
            masterKey = unwrapped;
            return masterKey;
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(stored, (byte) 0);
        }
    }

    /**
     * Walks the account root without accepting linked/special paths and refuses a new master-key epoch if
     * any encrypted files remain. This protects recoverability after key-file loss rather than attempting
     * to decrypt files with a newly generated unrelated key.
     *
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void requireUnencryptedStorage() throws IOException {
        Files.walkFileTree(root, new java.nio.file.SimpleFileVisitor<Path>() {
            /**
             * Performs the pre visit directory operation for the encrypted account storage.
             *
             * @param directory the directory supplied to this operation
             * @param attributes the attributes supplied to this operation
             * @return the result described above
             * @throws IOException if input/output, stored-state validation or resource handling fails
             */
            @Override
            public java.nio.file.FileVisitResult preVisitDirectory(Path directory,
                    java.nio.file.attribute.BasicFileAttributes attributes) throws IOException {
                SecureFiles.rejectLinks(directory);
                return java.nio.file.FileVisitResult.CONTINUE;
            }

            /**
             * Performs the visit file operation for the encrypted account storage.
             *
             * @param file the file supplied to this operation
             * @param attributes the attributes supplied to this operation
             * @return the result described above
             * @throws IOException if input/output, stored-state validation or resource handling fails
             */
            @Override
            public java.nio.file.FileVisitResult visitFile(Path file,
                    java.nio.file.attribute.BasicFileAttributes attributes) throws IOException {
                SecureFiles.rejectLinks(file);
                if (attributes.isRegularFile() && isEncrypted(file)) {
                    throw new IOException("Local master key is missing but encrypted files remain; restore it from backup");
                }
                return java.nio.file.FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * Stores the master key with Windows per-user DPAPI when available, using fixed nonsecret entropy and
     * UI-forbidden mode. DPAPI failure aborts the write rather than falling back to a raw key on Windows.
     * Other platforms retain raw key bytes in owner-only private storage; temporary protected-key copies
     * are overwritten.
     *
     * @param key the cryptographic key material for this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void writeMasterKey(byte[] key) throws IOException {
        byte mode = KEY_OWNER_ONLY;
        byte[] protectedKey = Arrays.copyOf(key, key.length);
        if (Platform.isWindows()) {
            try {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(protectedKey, (byte) 0);
                /*
                 * Calls Windows per-user DPAPI through JNA with the fixed nonsecret entropy label and UI-forbidden
                 * mode. The current Windows account supplies the protection boundary; native failure aborts instead of
                 * silently writing an unprotected replacement key.
                 */
                protectedKey = Crypt32Util.cryptProtectData(key, DPAPI_ENTROPY,
                        WinCrypt.CRYPTPROTECT_UI_FORBIDDEN, "Krypt04Mcg local master key", null);
                mode = KEY_DPAPI;
            } catch (RuntimeException | LinkageError e) {
                throw new IOException("Windows DPAPI could not protect the local master key", e);
            }
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write(KEY_MAGIC);
            out.writeByte(mode);
            out.write(protectedKey);
            SecureFiles.atomicWrite(masterKeyFile, bytes.toByteArray());
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(protectedKey, (byte) 0);
        }
    }

    /**
     * Unwraps a Windows DPAPI key under the current Windows user with the matching nonsecret entropy label
     * and no interactive prompt. Other operating systems and native DPAPI failures produce IOExceptions;
     * no cross-platform or plaintext fallback is attempted.
     *
     * @param protectedKey the protected key supplied to this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static byte[] unprotectWithDpapi(byte[] protectedKey) throws IOException {
        if (!Platform.isWindows()) {
            throw new IOException("This master key is protected by Windows DPAPI and cannot be opened on this OS");
        }
        try {
            /*
             * Calls Windows DPAPI with the same entropy/context used at protection time. Unwrapping depends on the
             * Windows user environment; unavailable native support or a different protection context fails rather
             * than becoming a plaintext fallback.
             */
            return Crypt32Util.cryptUnprotectData(protectedKey, DPAPI_ENTROPY,
                    WinCrypt.CRYPTPROTECT_UI_FORBIDDEN, null);
        } catch (RuntimeException | LinkageError e) {
            throw new IOException("Windows DPAPI could not unlock the local master key", e);
        }
    }

    /**
     * Normalizes a sensitive file path, requires it to remain under the configured account root, rejects
     * links in the path and encodes the relative path as stable UTF-8 AAD. This provides logical file
     * binding; path checks do not establish an atomic directory-handle sandbox against concurrent
     * filesystem changes.
     *
     * @param path the filesystem path used by this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private byte[] label(Path path) throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        if (!normalized.startsWith(root)) {
            throw new IOException("Sensitive file is outside the configured storage root: " + path);
        }
        SecureFiles.rejectLinks(normalized);
        return root.relativize(normalized).toString().replace('\\', '/').getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Performs the starts with operation for the encrypted account storage.
     *
     * @param value the value supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean startsWith(byte[] value, byte[] prefix) {
        return value.length >= prefix.length
                && ByteBuffer.wrap(value, 0, prefix.length).equals(ByteBuffer.wrap(prefix));
    }
}
