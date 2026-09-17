package dev.krypt04mcg.client;

import dev.krypt04mcg.protocol.ChatFragmentPayload;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

/** Same wire fields as both directions of the existing chat relay channel. */
public record NeoChatPayload(String peer, String fragment, int version) implements CustomPacketPayload {
    public static final Type<NeoChatPayload> TYPE = new Type<>(ChatFragmentPayload.CHANNEL);
    public static final StreamCodec<FriendlyByteBuf, NeoChatPayload> CODEC = StreamCodec.of(
            (buf, payload) -> {
                buf.writeUtf(payload.peer());
                buf.writeUtf(payload.fragment());
                buf.writeVarInt(payload.version());
            },
            buf -> new NeoChatPayload(buf.readUtf(), buf.readUtf(), buf.readVarInt()));

    @Override public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
