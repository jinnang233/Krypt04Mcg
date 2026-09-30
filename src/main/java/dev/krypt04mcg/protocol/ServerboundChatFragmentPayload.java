package dev.krypt04mcg.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

public record ServerboundChatFragmentPayload(String receiver, String fragment, int version)
        implements CustomPacketPayload {
    public static final Type<ServerboundChatFragmentPayload> TYPE = new Type<>(ChatFragmentPayload.CHANNEL);
    public static final StreamCodec<FriendlyByteBuf, ServerboundChatFragmentPayload> CODEC = StreamCodec.of(
            (buf, payload) -> {
                buf.writeUtf(payload.receiver(), 16);
                buf.writeUtf(payload.fragment(), dev.krypt04mcg.fragment.FragmentService.MAX_CHAT_MESSAGE_LENGTH);
                buf.writeVarInt(payload.version());
            },
            buf -> new ServerboundChatFragmentPayload(buf.readUtf(16), buf.readUtf(dev.krypt04mcg.fragment.FragmentService.MAX_CHAT_MESSAGE_LENGTH), buf.readVarInt()));

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
