package dev.krypt04mcg.protocol;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.crypto.*;
import dev.krypt04mcg.model.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PacketLayoutTest {
    @Test void rejectsFieldsThatAreAbsentFromTheAuthenticatedWireLayout() throws Exception {
        var codec = new PacketCodec();
        var crypto = new CryptoService();
        var p = crypto.encryptWithSession("Bob", "Alice", new byte[32], "AAAAAAAAAAAAAAAAAAAAAA", 0,
                "hello", false, AeadAlgorithm.AES_256_GCM);
        for (var changed : List.of(
                copy(p, PacketType.SESSION_MESSAGE, p.algorithms(), new byte[]{1}, (short) 0, p.sessionId(), 0),
                copy(p, PacketType.SESSION_MESSAGE, new AlgorithmSuite("ML-KEM-768", "NONE", "AES-256-GCM", "HKDF-SHA256"),
                        new byte[0], (short) 0, p.sessionId(), 0),
                copy(p, PacketType.SESSION_MESSAGE, p.algorithms(), new byte[0], (short) 2, p.sessionId(), 0),
                copy(p, PacketType.KEM_MESSAGE, p.algorithms(), new byte[]{1}, (short) 0, p.sessionId(), 7),
                copy(p, PacketType.KEM_MESSAGE, new AlgorithmSuite("ML-KEM-768", "ML-DSA-44", "AES-256-GCM", "HKDF-SHA256"),
                        new byte[]{1}, (short) 0, "", 0))) {
            assertThrows(IllegalArgumentException.class, () -> codec.encode(changed));
            assertThrows(IllegalArgumentException.class, () -> codec.aadFor(changed));
            assertThrows(CryptoException.class, () -> crypto.decryptWithSession(changed,
                    "Bob", "Alice", new byte[32], p.sessionId(), 0));
        }
    }

    @Test void decoderRejectsInjectedKemBytesInSessionPacket() throws Exception {
        var codec = new PacketCodec();
        var p = new CryptoService().encryptWithSession("Bob", "Alice", new byte[32], "AAAAAAAAAAAAAAAAAAAAAA", 0,
                "hello", false, AeadAlgorithm.AES_256_GCM);
        byte[] valid = codec.encode(p);
        // The session wire prefix equals AAD, followed by nonce length/nonce and the empty KEM length.
        int kemLength = codec.aadFor(p).length + 2 + p.nonce().length;
        byte[] injected = new byte[valid.length + 1];
        System.arraycopy(valid, 0, injected, 0, kemLength + 4);
        injected[kemLength + 3] = 1;
        injected[kemLength + 4] = 42;
        System.arraycopy(valid, kemLength + 4, injected, kemLength + 5, valid.length - kemLength - 4);
        assertThrows(IllegalArgumentException.class, () -> codec.decode(injected));
        assertArrayEquals(p.ciphertext(), codec.decode(valid).ciphertext());
    }

    private EncryptedPacket copy(EncryptedPacket p, PacketType type, AlgorithmSuite algorithms, byte[] kem,
                                 short fragment, String sessionId, long sequence) {
        return new EncryptedPacket(p.protocolVersion(), type, p.flags(), p.sender(), p.receiver(), p.timestampMillis(),
                p.messageId(), fragment, (short) 1, algorithms, p.nonce(), kem, p.ciphertext(), p.signature(), sessionId, sequence);
    }
}
