package dev.krypt04mcg.protocol;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ChatPayloadBoundsTest {
    @Test void boundsAreEnforcedWhenReadingAndWritingBothDirections() {
        for (String[] fields : new String[][]{{"a".repeat(17), "fragment"}, {"Alice", "x".repeat(257)}}) {
            var buffer = new FriendlyByteBuf(Unpooled.buffer());
            try {
                // Simulate an older or malicious relay using Minecraft's generous default limits.
                buffer.writeUtf(fields[0]); buffer.writeUtf(fields[1]); buffer.writeVarInt(4);
                assertThrows(RuntimeException.class, () -> ClientboundChatFragmentPayload.CODEC.decode(buffer));
                buffer.readerIndex(0);
                assertThrows(RuntimeException.class, () -> ServerboundChatFragmentPayload.CODEC.decode(buffer));
                buffer.clear();
                assertThrows(RuntimeException.class, () -> ClientboundChatFragmentPayload.CODEC.encode(buffer,
                        new ClientboundChatFragmentPayload(fields[0], fields[1], 4)));
                buffer.clear();
                assertThrows(RuntimeException.class, () -> ServerboundChatFragmentPayload.CODEC.encode(buffer,
                        new ServerboundChatFragmentPayload(fields[0], fields[1], 4)));
            } finally { buffer.release(); }
        }
    }

    @Test void maximumLegalFragmentKeepsTheExistingWireFormat() {
        var buffer = new FriendlyByteBuf(Unpooled.buffer());
        try {
            var sent = new ServerboundChatFragmentPayload("a".repeat(16), "x".repeat(256), 4);
            ServerboundChatFragmentPayload.CODEC.encode(buffer, sent);
            assertEquals(sent.receiver(), buffer.readUtf());
            assertEquals(sent.fragment(), buffer.readUtf());
            assertEquals(4, buffer.readVarInt());
            assertEquals(0, buffer.readableBytes());
            buffer.readerIndex(0);
            var received = ClientboundChatFragmentPayload.CODEC.decode(buffer);
            assertEquals(sent.fragment(), received.fragment());
        } finally { buffer.release(); }
    }
}
