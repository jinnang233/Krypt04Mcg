package dev.krypt04mcg.protocol;

import com.google.gson.Gson;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.util.*;
import java.util.UUID;
import java.util.Arrays;

/** Only the transport envelope is interpreted; application bytes remain opaque. */
public final class DataTransferCodec {
    private final CryptoService crypto = new CryptoService(FileTransferCodec.MAX_ENVELOPE_BYTES);
    private final PacketCodec packets = new PacketCodec(FileTransferCodec.MAX_ENVELOPE_BYTES + 65536);
    private final Gson gson = JsonSupport.prettyGson();

    public String encrypt(String channel, byte[] data, PublicIdentity receiver, LocalKeyMaterial sender,
                          AeadAlgorithm algorithm) throws Exception {
        return encrypt(new Envelope("krypt04mcg:data:v1", channel, Base64Url.encode(data), null, null), receiver, sender, algorithm);
    }

    public String encrypt(UUID transferId, String channel, byte[] data, PublicIdentity receiver,
                          LocalKeyMaterial sender, AeadAlgorithm algorithm) throws Exception {
        return encrypt(new Envelope("krypt04mcg:data:v2", channel, Base64Url.encode(data), transferId.toString(), Kind.DATA),
                receiver, sender, algorithm);
    }

    public String receipt(UUID transferId, Kind kind, PublicIdentity receiver, LocalKeyMaterial sender,
                          AeadAlgorithm algorithm) throws Exception {
        if (kind != Kind.ACK && kind != Kind.NACK) throw new IllegalArgumentException("Invalid receipt");
        return encrypt(new Envelope("krypt04mcg:data:v2", null, null, transferId.toString(), kind), receiver, sender, algorithm);
    }

    public String exchange(UUID id, byte[] packet, PublicIdentity receiver, LocalKeyMaterial sender,
                           AeadAlgorithm algorithm) throws Exception {
        return encrypt(new Envelope("krypt04mcg:data:v2", null, Base64Url.encode(packet), id.toString(), Kind.EXCHANGE),
                receiver, sender, algorithm);
    }

    public byte[] encodePacket(EncryptedPacket packet) { return packets.encode(packet); }
    public EncryptedPacket decodePacket(byte[] packet) { return packets.decode(packet); }

    public String encryptSession(UUID id, String channel, byte[] data, Kind kind, PublicIdentity receiver,
                                  LocalKeyMaterial sender, SessionRecord session, long sequence, AeadAlgorithm algorithm) throws Exception {
        if (kind == Kind.EXCHANGE) throw new IllegalArgumentException("Handshake must be signed");
        byte[] key = sessionKey(session);
        try {
            var envelope = new Envelope("krypt04mcg:data:session:v1", channel, data == null ? null : Base64Url.encode(data), id.toString(), kind);
            return Base64Url.encode(packets.encode(crypto.encryptWithSession(receiver.owner(), sender.kemPublicKey().owner(),
                    key, session.sessionId(), sequence, gson.toJson(envelope), false, algorithm)));
        } finally { Arrays.fill(key, (byte) 0); }
    }

    public Data decryptSession(EncryptedPacket packet, LocalKeyMaterial local, PublicIdentity peer, SessionRecord session) throws Exception {
        byte[] key = sessionKey(session);
        try {
            Data data = parse(crypto.decryptWithSession(packet, local.kemPublicKey().owner(), peer.owner(), key,
                    session.sessionId(), packet.sequence()), true);
            if ((packet.sequence() & 1) != (data.kind() == Kind.DATA ? 0 : 1)) throw new IllegalArgumentException("Invalid sequence lane");
            return data;
        } finally { Arrays.fill(key, (byte) 0); }
    }

    private byte[] sessionKey(SessionRecord session) throws Exception {
        byte[] secret = Base64Url.decode(session.secret());
        try { return crypto.deriveDataSessionSecret(secret, Base64Url.decode(session.sessionId())); }
        finally { Arrays.fill(secret, (byte) 0); }
    }

    private String encrypt(Envelope envelope, PublicIdentity receiver, LocalKeyMaterial sender,
                           AeadAlgorithm algorithm) throws Exception {
        return Base64Url.encode(packets.encode(crypto.encryptFor(receiver, sender, sender.kemPublicKey().owner(),
                gson.toJson(envelope), true, false, algorithm)));
    }

    public EncryptedPacket packet(String encoded, String sender, long now) {
        if (encoded.length() > FileTransferCodec.MAX_CHUNKS * OptionalTransferAssembler.CHUNK)
            throw new IllegalArgumentException("Envelope too large");
        var packet = packets.decode(Base64Url.decode(encoded));
        if (packet.type() != PacketType.SESSION_MESSAGE) return new FileTransferCodec().packet(encoded, sender, now);
        if (packet.protocolVersion() != EncryptedPacket.VERSION || packet.flags() != 0 || packet.signed()
                || !sender.equalsIgnoreCase(packet.sender()) || packet.timestampMillis() < now - 300000
                || packet.timestampMillis() > now + 60000) throw new IllegalArgumentException("Invalid session envelope");
        return packet;
    }

    public Data decrypt(EncryptedPacket packet, LocalKeyMaterial receiver, PublicIdentity sender) throws Exception {
        return parse(crypto.decrypt(packet, receiver, sender), false);
    }

    private Data parse(String plaintext, boolean session) {
        Envelope envelope = gson.fromJson(plaintext, Envelope.class);
        if (envelope == null) throw new IllegalArgumentException("Invalid API envelope");
        boolean legacy = !session && "krypt04mcg:data:v1".equals(envelope.domain);
        UUID id = null;
        Kind kind = Kind.DATA;
        if (!legacy) {
            if (!(session ? "krypt04mcg:data:session:v1" : "krypt04mcg:data:v2").equals(envelope.domain)
                    || envelope.transferId == null || envelope.kind == null)
                throw new IllegalArgumentException("Invalid API envelope");
            id = UUID.fromString(envelope.transferId);
            if (!id.toString().equals(envelope.transferId)) throw new IllegalArgumentException("Invalid transfer ID");
            kind = envelope.kind;
        }
        if (kind == Kind.EXCHANGE) {
            if (session || envelope.channel != null || envelope.data == null) throw new IllegalArgumentException("Invalid exchange");
            return new Data(null, Base64Url.decode(envelope.data), id, kind);
        }
        if (kind != Kind.DATA) {
            if (envelope.channel != null || envelope.data != null) throw new IllegalArgumentException("Invalid receipt");
            return new Data(null, null, id, kind);
        }
        if (envelope.channel == null || envelope.data == null) throw new IllegalArgumentException("Invalid API data");
        return new Data(envelope.channel, Base64Url.decode(envelope.data), id, kind);
    }

    public enum Kind { DATA, ACK, NACK, EXCHANGE }
    private record Envelope(String domain, String channel, String data, String transferId, Kind kind) {}
    public record Data(String channel, byte[] bytes, UUID transferId, Kind kind) {}
}
