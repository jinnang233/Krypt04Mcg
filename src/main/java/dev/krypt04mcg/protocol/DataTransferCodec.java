package dev.krypt04mcg.protocol;

import com.google.gson.Gson;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.util.*;
import java.util.UUID;

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

    private String encrypt(Envelope envelope, PublicIdentity receiver, LocalKeyMaterial sender,
                           AeadAlgorithm algorithm) throws Exception {
        return Base64Url.encode(packets.encode(crypto.encryptFor(receiver, sender, sender.kemPublicKey().owner(),
                gson.toJson(envelope), true, false, algorithm)));
    }

    public EncryptedPacket packet(String encoded, String sender, long now) {
        // Reuse the signed KEM envelope checks and existing transport size limits.
        return new FileTransferCodec().packet(encoded, sender, now);
    }

    public Data decrypt(EncryptedPacket packet, LocalKeyMaterial receiver, PublicIdentity sender) throws Exception {
        Envelope envelope = gson.fromJson(crypto.decrypt(packet, receiver, sender), Envelope.class);
        if (envelope == null) throw new IllegalArgumentException("Invalid API envelope");
        boolean legacy = "krypt04mcg:data:v1".equals(envelope.domain);
        UUID id = null;
        Kind kind = Kind.DATA;
        if (!legacy) {
            if (!"krypt04mcg:data:v2".equals(envelope.domain) || envelope.transferId == null || envelope.kind == null)
                throw new IllegalArgumentException("Invalid API envelope");
            id = UUID.fromString(envelope.transferId);
            if (!id.toString().equals(envelope.transferId)) throw new IllegalArgumentException("Invalid transfer ID");
            kind = envelope.kind;
        }
        if (kind != Kind.DATA) {
            if (envelope.channel != null || envelope.data != null) throw new IllegalArgumentException("Invalid receipt");
            return new Data(null, null, id, kind);
        }
        if (envelope.channel == null || envelope.data == null) throw new IllegalArgumentException("Invalid API data");
        return new Data(envelope.channel, Base64Url.decode(envelope.data), id, kind);
    }

    public enum Kind { DATA, ACK, NACK }
    private record Envelope(String domain, String channel, String data, String transferId, Kind kind) {}
    public record Data(String channel, byte[] bytes, UUID transferId, Kind kind) {}
}
