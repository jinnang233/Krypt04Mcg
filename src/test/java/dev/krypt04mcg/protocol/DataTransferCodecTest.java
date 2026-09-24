package dev.krypt04mcg.protocol;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import org.junit.jupiter.api.Test;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;

class DataTransferCodecTest {
    @Test void arbitraryBytesAndEmptyPayloadSurviveEncryptedFragmentedRoundTrip() throws Exception {
        var crypto = new CryptoService();
        var alice = crypto.generateLocalKeys("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var codec = new DataTransferCodec();
        byte[] binary = new byte[100000];
        new Random(42).nextBytes(binary);
        for (byte[] input : new byte[][] { binary, new byte[0] }) {
            String encrypted = codec.encrypt("othermod:二进制", input, identity(bob), alice, AeadAlgorithm.AES_256_GCM);
            var fragments = OptionalTransferAssembler.split(encrypted, FileTransferCodec.MAX_CHUNKS);
            var assembler = new OptionalTransferAssembler(FileTransferCodec.MAX_CHUNKS, 4);
            String assembled = null;
            for (String fragment : fragments) assembled = assembler.accept("Alice", fragment, 0).orElse(null);
            var packet = codec.packet(assembled, "Alice", System.currentTimeMillis());
            assertTrue(packet.signed());
            var decoded = codec.decrypt(packet, bob, identity(alice));
            assertEquals("othermod:二进制", decoded.channel());
            assertArrayEquals(input, decoded.bytes());
            assertThrows(Exception.class, () -> codec.packet(encrypted, "Mallory", System.currentTimeMillis()));
            assertThrows(Exception.class, () -> codec.packet(encrypted, "Alice", System.currentTimeMillis() + 360000));
            packet.signature()[0] ^= 1;
            assertThrows(Exception.class, () -> codec.decrypt(packet, bob, identity(alice)));
        }
        // A valid signed file envelope must never be mistaken for an API message.
        String file = new FileTransferCodec().encrypt("name", binary, identity(bob), alice, AeadAlgorithm.AES_256_GCM);
        assertThrows(IllegalArgumentException.class,
                () -> codec.decrypt(codec.packet(file, "Alice", System.currentTimeMillis()), bob, identity(alice)));
    }

    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(), keys.kemPublicKey(), keys.signaturePublicKey());
    }
}
