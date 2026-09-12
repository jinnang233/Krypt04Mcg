package dev.krypt04mcg.protocol;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.*;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.util.Base64Url;
import org.junit.jupiter.api.Test;
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;

class FileTransferCodecTest {
    @Test void transfersTenMiBWithSignatureAndKeepsChatLimits() throws Exception {
        var crypto = new CryptoService();
        var alice = crypto.generateLocalKeys("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var files = new FileTransferCodec();
        byte[] data = new byte[FileTransferCodec.MAX_FILE_BYTES];
        new Random(42).nextBytes(data);
        String envelope = files.encrypt("测试.bin", data, identity(bob), alice, AeadAlgorithm.AES_256_GCM);
        var parts = OptionalTransferAssembler.split(envelope, FileTransferCodec.MAX_CHUNKS);
        assertTrue(parts.size() > OptionalTransferAssembler.MAX_CHUNKS);
        var assembler = new OptionalTransferAssembler(FileTransferCodec.MAX_CHUNKS, 1);
        String assembled = null;
        for (String part : parts) assembled = assembler.accept("Alice", part, 0).orElse(null);
        assertEquals(envelope, assembled);
        var packet = files.packet(assembled, "Alice", System.currentTimeMillis());
        var decoded = files.decrypt(packet, bob, identity(alice));
        assertEquals("测试.bin", decoded.name());
        assertArrayEquals(data, Base64Url.decode(decoded.data()));
        assertThrows(IllegalArgumentException.class, () -> new PacketCodec().decode(Base64Url.decode(envelope)));
        assertThrows(CryptoException.class, () -> crypto.encryptFor(identity(bob), alice, "Alice",
                "x".repeat(CryptoService.MAX_PLAINTEXT_BYTES + 1), true));
        assertThrows(IllegalArgumentException.class, () -> files.encrypt("large.bin",
                new byte[FileTransferCodec.MAX_FILE_BYTES + 1], identity(bob), alice, AeadAlgorithm.AES_256_GCM));
    }

    @Test void rejectsTamperingWrongSenderAndExpiredFiles() throws Exception {
        var crypto = new CryptoService();
        var alice = crypto.generateLocalKeys("Alice", "alice", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var bob = crypto.generateLocalKeys("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var files = new FileTransferCodec();
        String envelope = files.encrypt("hello.txt", new byte[]{1, 2, 3}, identity(bob), alice, AeadAlgorithm.AES_256_GCM);
        long now = System.currentTimeMillis();
        assertThrows(IllegalArgumentException.class, () -> files.packet(envelope, "Mallory", now));
        assertThrows(IllegalArgumentException.class, () -> files.packet(envelope, "Alice", now + 360000));
        var packet = files.packet(envelope, "Alice", now);
        packet.ciphertext()[0] ^= 1;
        assertThrows(CryptoException.class, () -> files.decrypt(packet, bob, identity(alice)));
    }

    private static PublicIdentity identity(LocalKeyMaterial keys) {
        return new PublicIdentity(keys.kemPublicKey().owner(), keys.kemPublicKey().uuid(), keys.kemPublicKey(), keys.signaturePublicKey());
    }
}
