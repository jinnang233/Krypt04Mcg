package dev.krypt04mcg.protocol;

import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PacketType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class PacketCodecTest {
    @Test
    void rejectsMalformedUtf8InsteadOfNormalizingAuthenticatedFields() {
        PacketCodec codec = new PacketCodec();
        EncryptedPacket packet = new EncryptedPacket((byte) 4, PacketType.SIGNED_KEM_MESSAGE, (byte) 1,
                "\uFFFD", "bob", 123L, bytes(16, 7), (short) 0, (short) 1, AlgorithmSuite.defaults(),
                bytes(12, 1), bytes(32, 2), bytes(64, 3), bytes(48, 4));
        byte[] encoded = codec.encode(packet);
        // A UTF-8 encoded surrogate previously normalized to the same authenticated string.
        encoded[5] = (byte) 0xed;
        encoded[6] = (byte) 0xa0;
        encoded[7] = (byte) 0x80;
        assertEquals(packet.sender(), new String(encoded, 5, 3, java.nio.charset.StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> codec.decode(encoded));
    }

    @Test
    void encoderUsesTheSameFieldSizeLimitsAsDecoder() {
        PacketCodec codec = new PacketCodec();
        for (EncryptedPacket packet : new EncryptedPacket[]{
                new EncryptedPacket((byte) 4, PacketType.SIGNED_KEM_MESSAGE, (byte) 1,
                        "a".repeat(4097), "bob", 123L, bytes(16, 7), (short) 0, (short) 1,
                        AlgorithmSuite.defaults(), bytes(12, 1), bytes(32, 2), bytes(64, 3), bytes(48, 4)),
                new EncryptedPacket((byte) 4, PacketType.SIGNED_KEM_MESSAGE, (byte) 1,
                        "alice", "bob", 123L, bytes(16, 7), (short) 0, (short) 1,
                        AlgorithmSuite.defaults(), bytes(12, 1), bytes(32, 2), new byte[1024 * 1024 + 1], bytes(48, 4))}) {
            assertThrows(IllegalStateException.class, () -> codec.encode(packet));
        }
    }

    @Test
    void packetEncodeDecodeRoundTrip() {
        PacketCodec codec = new PacketCodec();
        EncryptedPacket packet = new EncryptedPacket((byte) 1, PacketType.SIGNED_KEM_MESSAGE, (byte) 1,
                "alice", "bob", 123L, bytes(16, 7), (short) 0, (short) 1, AlgorithmSuite.defaults(),
                bytes(12, 1), bytes(32, 2), bytes(64, 3), bytes(48, 4));

        EncryptedPacket decoded = codec.decode(codec.encode(packet));

        assertEquals(packet.sender(), decoded.sender());
        assertEquals(packet.receiver(), decoded.receiver());
        assertEquals(packet.type(), decoded.type());
        assertArrayEquals(packet.messageId(), decoded.messageId());
        assertArrayEquals(packet.ciphertext(), decoded.ciphertext());
        assertArrayEquals(packet.signature(), decoded.signature());
    }

    private static byte[] bytes(int length, int value) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) value;
        }
        return bytes;
    }
}
