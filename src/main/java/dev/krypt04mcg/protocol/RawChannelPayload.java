package dev.krypt04mcg.protocol;

import java.util.List;
import java.util.stream.IntStream;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/** Minecraft's payload boundary is the AEAD record boundary. No inner header or length field. */
public record RawChannelPayload(int slot, byte[] ciphertext) implements CustomPacketPayload {
    public static final String NAMESPACE = "krypt04mcg_stream";
    public static final int MAX_PLAINTEXT = 16 * 1024, TAG_BYTES = 16;
    /**
     * Performs the channel count operation for the raw channel payload.
     *
     * @param configured the configured supplied to this operation
     * @return the result described above
     */
    public static int channelCount(int configured) { return Math.clamp(configured, 1, 256); }
    /**
     * Performs the types operation for the raw channel payload.
     *
     * @param count the required number of frame components
     * @return the result described above
     */
    public static List<Type<RawChannelPayload>> types(int count) {
        return IntStream.range(0, channelCount(count)).mapToObj(RawChannelPayload::typeFor).toList();
    }
    /**
     * Performs the type for operation for the raw channel payload.
     *
     * @param slot the slot supplied to this operation
     * @return the result described above
     */
    public static Type<RawChannelPayload> typeFor(int slot) {
        if (slot < 0 || slot >= 256) throw new IllegalArgumentException("Invalid channel slot");
        return new Type<>(Identifier.fromNamespaceAndPath(NAMESPACE, "data/" + slot));
    }
    /**
     * Creates a raw channel payload with the supplied dependencies and initial state.
     *
     * @param slot the slot supplied to this operation
     * @param ciphertext the encoded ciphertext to authenticate or decode
     */
    public RawChannelPayload {
        if (slot < 0 || slot >= 256 || ciphertext.length < TAG_BYTES || ciphertext.length > MAX_PLAINTEXT + TAG_BYTES)
            throw new IllegalArgumentException("Invalid encrypted record");
        ciphertext = ciphertext.clone();
    }
    /**
     * Performs the codec operation for the raw channel payload.
     *
     * @param slot the slot supplied to this operation
     * @return the result described above
     */
    public static StreamCodec<FriendlyByteBuf, RawChannelPayload> codec(int slot) {
        return StreamCodec.of((buf, p) -> buf.writeBytes(p.ciphertext), buf -> {
            int length = buf.readableBytes();
            if (length < TAG_BYTES || length > MAX_PLAINTEXT + TAG_BYTES) throw new IllegalArgumentException("Invalid record size");
            byte[] bytes = new byte[length]; buf.readBytes(bytes);
            return new RawChannelPayload(slot, bytes);
        });
    }
    /**
     * Returns the type value used by the raw channel payload.
     *
     * @return the result described above
     */
    @Override public Type<RawChannelPayload> type() { return typeFor(slot); }
}
