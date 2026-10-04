package dev.krypt04mcg.protocol;

import java.util.UUID;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/** Only this dedicated channel carries allocation, signed exchange and stream lifecycle metadata. */
public record ControlPayload(Kind kind, String peer, UUID id, int slot, String channel,
                             String sessionId, long sequence, byte[] body) implements CustomPacketPayload {
    public enum Kind { EXCHANGE, OPEN, ASSIGNED, READY, END, RESET, ABORT }
    public static final int MAX_BODY = 30000;
    public static final Type<ControlPayload> TYPE = new Type<>(Identifier.fromNamespaceAndPath(RawChannelPayload.NAMESPACE, "control"));
    public static final StreamCodec<FriendlyByteBuf, ControlPayload> CODEC = StreamCodec.of((b, p) -> {
        b.writeEnum(p.kind); b.writeUtf(p.peer, 16); b.writeUUID(p.id); b.writeInt(p.slot);
        b.writeUtf(p.channel, 256); b.writeUtf(p.sessionId, 64); b.writeLong(p.sequence); b.writeByteArray(p.body);
    }, b -> new ControlPayload(b.readEnum(Kind.class), b.readUtf(16), b.readUUID(), b.readInt(),
            b.readUtf(256), b.readUtf(64), b.readLong(), b.readByteArray(MAX_BODY)));
    public ControlPayload {
        if (!peer.matches("[A-Za-z0-9_]{1,16}") || slot < -1 || slot >= 256 || channel.length() > 256
                || sessionId.length() > 64 || sequence < 0 || body.length > MAX_BODY)
            throw new IllegalArgumentException("Invalid stream control");
        body = body.clone();
    }
    public ControlPayload routed(String source, Kind routedKind, int assignedSlot) {
        return new ControlPayload(routedKind, source, id, assignedSlot, channel, sessionId, sequence, body);
    }
    @Override public Type<ControlPayload> type() { return TYPE; }
}
