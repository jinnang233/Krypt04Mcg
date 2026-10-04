package dev.krypt04mcg.crypto;

import java.util.Arrays;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/** Thin adapter to BouncyCastle's fixed XChaCha20-Poly1305 implementation. */
public final class XChaCha20Poly1305 {
    private XChaCha20Poly1305() {}
    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws CryptoException {
        return apply(true, key, nonce, aad, plaintext);
    }
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) throws CryptoException {
        return apply(false, key, nonce, aad, ciphertext);
    }
    private static byte[] apply(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws CryptoException {
        if (key == null || key.length != 32 || nonce == null || nonce.length != 24 || input == null)
            throw new CryptoException("Invalid XChaCha20 key, nonce or input");
        if (!encrypt && input.length < 16) throw new CryptoException("Missing Poly1305 tag");
        var cipher = new org.bouncycastle.crypto.modes.XChaCha20Poly1305();
        byte[] result = null;
        boolean complete = false;
        try {
            cipher.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            result = new byte[cipher.getOutputSize(input.length)];
            int count = cipher.processBytes(input, 0, input.length, result, 0);
            cipher.doFinal(result, count);
            complete = true;
            return result;
        } catch (InvalidCipherTextException | IllegalArgumentException e) {
            throw new CryptoException("XChaCha20-Poly1305 authentication failed", e);
        } finally {
            // Streaming decryption can write plaintext before doFinal verifies the tag.
            if (!complete && result != null) Arrays.fill(result, (byte) 0);
        }
    }
}
