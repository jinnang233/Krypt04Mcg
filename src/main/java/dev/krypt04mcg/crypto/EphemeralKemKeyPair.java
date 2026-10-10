package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;

import java.util.Arrays;

public final class EphemeralKemKeyPair implements AutoCloseable {
    private final KemAlgorithm algorithm;
    private final byte[] publicKey;
    private final byte[] privateKey;
    private boolean destroyed;

    /**
     * Copies temporary public/private KEM encodings into an independently closeable holder tied to the
     * selected suite. The retained private bytes are secret; closing the holder overwrites its copies but
     * cannot erase other provider or caller copies.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param publicKey the public key whose declared suite is checked before use
     * @param privateKey the private key material used by the selected primitive
     */
    EphemeralKemKeyPair(KemAlgorithm algorithm, byte[] publicKey, byte[] privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey.clone();
        this.privateKey = privateKey.clone();
    }

    /**
     * Returns the algorithm value used by the ephemeral kem key pair.
     *
     * @return the result described above
     */
    public KemAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns a copy of the pending ephemeral public-key encoding while the holder is available. This is
     * an exchange key, not a permanent trust anchor.
     *
     * @return the resulting array produced by this operation
     */
    public synchronized byte[] publicKey() {
        ensureAvailable();
        return publicKey.clone();
    }

    /**
     * Returns a copy of the pending ephemeral private-key encoding only while the holder remains
     * available. The caller owns that sensitive copy and must erase it after decoding or use.
     *
     * @return the resulting array produced by this operation
     */
    synchronized byte[] privateKey() {
        ensureAvailable();
        return privateKey.clone();
    }

    /**
     * Returns the recorded destroyed for the ephemeral kem key pair.
     *
     * @return whether the condition or operation described above succeeds
     */
    public synchronized boolean destroyed() {
        return destroyed;
    }

    /**
     * Destroys the holder by overwriting retained public/private encoding arrays and marking it
     * unavailable. Later accessor calls fail; copies already returned to callers cannot be erased by this
     * holder.
     */
    @Override
    public synchronized void close() {
        /*
         * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
         * immutable Strings, returned copies and provider/native key objects may retain other copies.
         */
        Arrays.fill(publicKey, (byte) 0);
        /*
         * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
         * immutable Strings, returned copies and provider/native key objects may retain other copies.
         */
        Arrays.fill(privateKey, (byte) 0);
        destroyed = true;
    }

    /**
     * Rejects access after the temporary key holder has been closed, avoiding accidental reuse of an
     * expired or completed handshake key.
     */
    private void ensureAvailable() {
        if (destroyed) {
            throw new IllegalStateException("Ephemeral KEM key has been destroyed");
        }
    }
}
