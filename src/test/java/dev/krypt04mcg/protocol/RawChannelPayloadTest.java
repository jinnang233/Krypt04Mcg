package dev.krypt04mcg.protocol;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RawChannelPayloadTest {
    /**
     * Verifies that minecraft payload contains exactly ciphertext and tag.
     */
    @Test void minecraftPayloadContainsExactlyCiphertextAndTag() {
        byte[] ciphertext = new byte[123];
        for (int i = 0; i < ciphertext.length; i++) ciphertext[i] = (byte) i;
        var buffer = new FriendlyByteBuf(Unpooled.buffer());
        try {
            var codec = RawChannelPayload.codec(7);
            codec.encode(buffer, new RawChannelPayload(7, ciphertext));
            assertEquals(ciphertext.length, buffer.readableBytes());
            byte[] wire = new byte[buffer.readableBytes()]; buffer.getBytes(0, wire);
            assertArrayEquals(ciphertext, wire);
            var decoded = codec.decode(buffer);
            assertEquals(7, decoded.slot()); assertArrayEquals(ciphertext, decoded.ciphertext());
            assertEquals(0, buffer.readableBytes());
            assertEquals("krypt04mcg_stream:data/7", decoded.type().id().toString());
        } finally { buffer.release(); }
    }
    /**
     * Verifies that rejects missing tag and oversized record before allocation.
     */
    @Test void rejectsMissingTagAndOversizedRecordBeforeAllocation() {
        for (int size : new int[]{15, RawChannelPayload.MAX_PLAINTEXT + RawChannelPayload.TAG_BYTES + 1}) {
            var buffer = new FriendlyByteBuf(Unpooled.wrappedBuffer(new byte[size]));
            try { assertThrows(IllegalArgumentException.class, () -> RawChannelPayload.codec(0).decode(buffer)); }
            finally { buffer.release(); }
        }
        assertEquals(1, RawChannelPayload.channelCount(-1));
        assertEquals(256, RawChannelPayload.channelCount(Integer.MAX_VALUE));
    }
}
