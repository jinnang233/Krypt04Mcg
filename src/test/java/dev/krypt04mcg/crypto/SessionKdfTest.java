package dev.krypt04mcg.crypto;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SessionKdfTest {
    /**
     * Verifies that existing session derivation remains compatible.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void existingSessionDerivationRemainsCompatible() throws Exception {
        byte[] secret = new byte[32], salt = new byte[16];
        for (int i = 0; i < secret.length; i++) secret[i] = (byte) i;
        for (int i = 0; i < salt.length; i++) salt[i] = (byte) i;
        var crypto = new CryptoService();
        assertEquals("5379f0b6228f9668c2162eb2ab50678af72cd1895c67156e54fee7ff6196f5df", HexFormat.of().formatHex(crypto.deriveSessionSecret(secret, salt)));
        assertEquals("43559096b55efa32188a11f5f91e23d4a109574cb64ecb3a1bc47564c3b6eaee", HexFormat.of().formatHex(crypto.deriveDataSessionSecret(secret, salt)));
    }
}
