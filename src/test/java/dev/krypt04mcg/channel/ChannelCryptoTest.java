package dev.krypt04mcg.channel;

import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.Base64Url;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ChannelCryptoTest {
    /**
     * Provides the session fixture operation used by the channel crypto test regression scenarios.
     *
     * @return the result described above
     */
    private SessionRecord session() {
        return new SessionRecord("Bob", "fingerprint", Base64Url.encode(new byte[16]),
                Instant.now(), Instant.now(), Base64Url.encode(new byte[32]), 0, 0);
    }

    /**
     * Verifies that identical endpoints cannot reuse directional keys and nonces.
     */
    @Test void identicalEndpointsCannotReuseDirectionalKeysAndNonces() {
        assertThrows(IllegalArgumentException.class, () ->
                new ChannelCrypto(session(), UUID.randomUUID(), 0, "test:stream", "Alice", "aLiCe"));
    }

    /**
     * Verifies that reflection fails but peer can decrypt.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void reflectionFailsButPeerCanDecrypt() throws Exception {
        UUID id = UUID.randomUUID();
        try (var alice = new ChannelCrypto(session(), id, 0, "test:stream", "Alice", "Bob");
             var bob = new ChannelCrypto(session(), id, 0, "test:stream", "Bob", "Alice")) {
            byte[] ciphertext = alice.encrypt(new byte[]{42});
            assertThrows(CryptoException.class, () -> alice.decrypt(ciphertext));
            assertEquals(0, alice.received());
            assertArrayEquals(new byte[]{42}, bob.decrypt(ciphertext));
        }
    }

    /**
     * Verifies that closed crypto cannot use erased keys.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void closedCryptoCannotUseErasedKeys() throws Exception {
        UUID id = UUID.randomUUID();
        var alice = new ChannelCrypto(session(), id, 0, "test:stream", "Alice", "Bob");
        try (var bob = new ChannelCrypto(session(), id, 0, "test:stream", "Bob", "Alice")) {
            byte[] ciphertext = bob.encrypt(new byte[]{42});
            alice.close();
            alice.close();
            assertThrows(CryptoException.class, () -> alice.encrypt(new byte[]{1}));
            assertThrows(CryptoException.class, () -> alice.decrypt(ciphertext));
            assertEquals(0, alice.sent());
            assertEquals(0, alice.received());
        }
    }
}
