package dev.krypt04mcg.channel;

import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.Base64Url;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ChannelCryptoTest {
    private SessionRecord session() {
        return new SessionRecord("Bob", "fingerprint", Base64Url.encode(new byte[16]),
                Instant.now(), Instant.now(), Base64Url.encode(new byte[32]), 0, 0);
    }

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
