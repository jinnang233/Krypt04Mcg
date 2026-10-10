package dev.krypt04mcg.crypto;

import java.util.Arrays;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/** Thin adapter to BouncyCastle's fixed XChaCha20-Poly1305 implementation. */
public final class XChaCha20Poly1305 {
    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private XChaCha20Poly1305() {}
    /**
     * Encrypts bytes with Bouncy Castle XChaCha20-Poly1305 using a 32-byte key, 24-byte nonce and supplied
     * AAD. The result includes a 16-byte Poly1305 tag; a nonce must not be reused under the same key.
     *
     * @param key the cryptographic key material for this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @param aad the additional authenticated data bound to the ciphertext
     * @param plaintext the plaintext bytes to encrypt or process
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws CryptoException {
        return apply(true, key, nonce, aad, plaintext);
    }
    /**
     * Authenticates and decrypts XChaCha20-Poly1305 ciphertext and AAD. Inputs must contain a tag, and
     * plaintext is returned only after final tag verification succeeds. A malformed record or tag failure
     * raises CryptoException.
     *
     * @param key the cryptographic key material for this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @param aad the additional authenticated data bound to the ciphertext
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) throws CryptoException {
        return apply(false, key, nonce, aad, ciphertext);
    }
    /**
     * Validates key, nonce and input sizes and delegates the primitive to Bouncy Castle with a 128-bit
     * tag. processBytes can emit tentative plaintext before doFinal authenticates it; the result buffer is
     * overwritten on every unsuccessful path and is returned only after successful finalization. This
     * cleanup is best effort within JVM memory.
     *
     * @param encrypt whether to encrypt rather than authenticate and decrypt
     * @param key the cryptographic key material for this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @param aad the additional authenticated data bound to the ciphertext
     * @param input the input bytes or stream consumed by the operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static byte[] apply(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws CryptoException {
        if (key == null || key.length != 32 || nonce == null || nonce.length != 24 || input == null)
            throw new CryptoException("Invalid XChaCha20 key, nonce or input");
        if (!encrypt && input.length < 16) throw new CryptoException("Missing Poly1305 tag");
        /*
         * Uses the BC XChaCha20-Poly1305 primitive instead of implementing cipher rounds locally. This adapter
         * requires a 256-bit key, 192-bit nonce and 128-bit tag; the enclosing stream context is passed as
         * authenticated data.
         */
        var cipher = new org.bouncycastle.crypto.modes.XChaCha20Poly1305();
        byte[] result = null;
        boolean complete = false;
        try {
            /*
             * Binds the key, tag length, nonce and AAD into the BC AEAD operation. The explicit nonce/context must
             * be the one expected by the protocol; the parameter object itself is not an authentication result.
             */
            cipher.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            result = new byte[cipher.getOutputSize(input.length)];
            int count = cipher.processBytes(input, 0, input.length, result, 0);
            /*
             * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
             * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
             * output when finalization fails.
             */
            cipher.doFinal(result, count);
            complete = true;
            return result;
        } catch (InvalidCipherTextException | IllegalArgumentException e) {
            throw new CryptoException("XChaCha20-Poly1305 authentication failed", e);
        } finally {
            // Streaming decryption can write plaintext before doFinal verifies the tag.
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            if (!complete && result != null) Arrays.fill(result, (byte) 0);
        }
    }
}
