package dev.krypt04mcg.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/** One complete encrypted stream frame. The relay replaces peer with the authenticated sender. */
public record TunnelPayload(String peer, byte[] envelope) implements CustomPacketPayload {
    public static final int MAX_BYTES = 24 * 1024;
    public static final Type<TunnelPayload> TYPE = new Type<>(Identifier.fromNamespaceAndPath("krypt04mcg", "tunnel"));
    public static final StreamCodec<FriendlyByteBuf, TunnelPayload> CODEC = StreamCodec.of(
            (buf, p) -> { buf.writeUtf(p.peer, 16); buf.writeByteArray(p.envelope); },
            buf -> new TunnelPayload(buf.readUtf(16), buf.readByteArray(MAX_BYTES)));
    public TunnelPayload {
        if (envelope.length > MAX_BYTES) throw new IllegalArgumentException("Tunnel envelope too large");
    }
    @Override public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
