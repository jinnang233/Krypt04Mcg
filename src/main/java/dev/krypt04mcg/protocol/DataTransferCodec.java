package dev.krypt04mcg.protocol;

import com.google.gson.Gson;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.util.*;

/** Only the transport envelope is interpreted; application bytes remain opaque. */
public final class DataTransferCodec {
    private final CryptoService crypto = new CryptoService(FileTransferCodec.MAX_ENVELOPE_BYTES);
    private final PacketCodec packets = new PacketCodec(FileTransferCodec.MAX_ENVELOPE_BYTES + 65536);
    private final Gson gson = JsonSupport.prettyGson();

    public String encrypt(String channel, byte[] data, PublicIdentity receiver, LocalKeyMaterial sender,
                          AeadAlgorithm algorithm) throws Exception {
        var envelope = new Envelope("krypt04mcg:data:v1", channel, Base64Url.encode(data));
        return Base64Url.encode(packets.encode(crypto.encryptFor(receiver, sender, sender.kemPublicKey().owner(),
                gson.toJson(envelope), true, false, algorithm)));
    }

    public EncryptedPacket packet(String encoded, String sender, long now) {
        // Reuse the signed KEM envelope checks and existing transport size limits.
        return new FileTransferCodec().packet(encoded, sender, now);
    }

    public Data decrypt(EncryptedPacket packet, LocalKeyMaterial receiver, PublicIdentity sender) throws Exception {
        Envelope envelope = gson.fromJson(crypto.decrypt(packet, receiver, sender), Envelope.class);
        if (envelope == null || !"krypt04mcg:data:v1".equals(envelope.domain)
                || envelope.channel == null || envelope.data == null)
            throw new IllegalArgumentException("Invalid API envelope");
        return new Data(envelope.channel, Base64Url.decode(envelope.data));
    }

    private record Envelope(String domain, String channel, String data) {}
    public record Data(String channel, byte[] bytes) {}
}
