package dev.krypt04mcg.protocol;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
public record PublicKeyPayload(String peer, String fragment, int version) implements CustomPacketPayload {
    public static final Type<PublicKeyPayload> TYPE = new Type<>(Identifier.fromNamespaceAndPath("krypt04mcg", "public_key"));
    public static final StreamCodec<FriendlyByteBuf, PublicKeyPayload> CODEC = StreamCodec.of(
        (buf, p) -> { buf.writeUtf(p.peer(), 16); buf.writeUtf(p.fragment(), 12100); buf.writeVarInt(p.version()); },
        buf -> new PublicKeyPayload(buf.readUtf(16), buf.readUtf(12100), buf.readVarInt()));
    @Override public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
