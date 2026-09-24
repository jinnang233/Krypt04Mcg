package dev.krypt04mcg.protocol;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
public record DataPayload(String peer, String fragment, int version) implements CustomPacketPayload {
    public static final Type<DataPayload> TYPE = new Type<>(Identifier.fromNamespaceAndPath("krypt04mcg", "data"));
    public static final StreamCodec<FriendlyByteBuf, DataPayload> CODEC = StreamCodec.of(
        (buf, p) -> { buf.writeUtf(p.peer(), 16); buf.writeUtf(p.fragment(), 12100); buf.writeVarInt(p.version()); },
        buf -> new DataPayload(buf.readUtf(16), buf.readUtf(12100), buf.readVarInt()));
    @Override public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
