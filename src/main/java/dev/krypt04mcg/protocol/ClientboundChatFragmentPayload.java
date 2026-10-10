package dev.krypt04mcg.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

public record ClientboundChatFragmentPayload(String sender, String fragment, int version)
        implements CustomPacketPayload {
    public static final Type<ClientboundChatFragmentPayload> TYPE = new Type<>(ChatFragmentPayload.CHANNEL);
    public static final StreamCodec<FriendlyByteBuf, ClientboundChatFragmentPayload> CODEC = StreamCodec.of(
            (buf, payload) -> {
                buf.writeUtf(payload.sender(), 16);
                buf.writeUtf(payload.fragment(), dev.krypt04mcg.fragment.FragmentService.MAX_CHAT_MESSAGE_LENGTH);
                buf.writeVarInt(payload.version());
            },
            buf -> new ClientboundChatFragmentPayload(buf.readUtf(16), buf.readUtf(dev.krypt04mcg.fragment.FragmentService.MAX_CHAT_MESSAGE_LENGTH), buf.readVarInt()));

    /**
     * Returns the type value used by the clientbound chat fragment payload.
     *
     * @return the result described above
     */
    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
