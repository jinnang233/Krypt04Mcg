package dev.krypt04mcg.protocol;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.util.Base64Url;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

/** A separate key domain from chat and the reliable Data API; all routing metadata is authenticated. */
public final class TunnelCodec {
    private final CryptoService crypto = new CryptoService(TunnelPayload.MAX_BYTES);
    private final PacketCodec packets = new PacketCodec(TunnelPayload.MAX_BYTES);

    public byte[] encrypt(SessionRecord session, String sender, String receiver, UUID stream, long lease,
                          long counter, byte[] frame, AeadAlgorithm algorithm) throws Exception {
        if (frame == null || (frame.length * 4L + 2) / 3 + 24 + 16 > TunnelPayload.MAX_BYTES)
            throw new IllegalArgumentException("Tunnel frame too large");
        byte[] key = key(session, stream, lease, sender, receiver);
        try {
            byte[] packet = packets.encode(crypto.encryptWithSession(receiver, sender, key,
                    session.sessionId(), counter, Base64Url.encode(frame), false, algorithm));
            if (packet.length > TunnelPayload.MAX_BYTES - 24)
                throw new IllegalArgumentException("Tunnel envelope too large");
            return ByteBuffer.allocate(24 + packet.length).putLong(stream.getMostSignificantBits())
                    .putLong(stream.getLeastSignificantBits()).putLong(lease).put(packet).array();
        } finally { Arrays.fill(key, (byte) 0); }
    }

    public Header header(byte[] envelope) {
        if (envelope.length < 25 || envelope.length > TunnelPayload.MAX_BYTES)
            throw new IllegalArgumentException("Invalid tunnel size");
        var in = ByteBuffer.wrap(envelope);
        UUID stream = new UUID(in.getLong(), in.getLong());
        long lease = in.getLong();
        var packet = packets.decode(Arrays.copyOfRange(envelope, 24, envelope.length));
        if (lease < 0 || packet.type() != PacketType.SESSION_MESSAGE || packet.flags() != 0 || packet.signed()
                || packet.sequence() < 0 || packet.sequence() == Long.MAX_VALUE)
            throw new IllegalArgumentException("Invalid tunnel metadata");
        return new Header(stream, lease, packet);
    }

    public byte[] decrypt(Header header, SessionRecord session, String receiver, String sender) throws Exception {
        byte[] key = key(session, header.stream, header.lease, sender, receiver);
        try {
            return Base64Url.decode(crypto.decryptWithSession(header.packet, receiver, sender, key,
                    session.sessionId(), header.packet.sequence()));
        } finally { Arrays.fill(key, (byte) 0); }
    }

    private byte[] key(SessionRecord session, UUID stream, long lease, String sender, String receiver) throws Exception {
        byte[] secret = Base64Url.decode(session.secret());
        try { return crypto.deriveTunnelSecret(secret, session.sessionId(), stream, lease, sender, receiver); }
        finally { Arrays.fill(secret, (byte) 0); }
    }
    public record Header(UUID stream, long lease, EncryptedPacket packet) {}
}
