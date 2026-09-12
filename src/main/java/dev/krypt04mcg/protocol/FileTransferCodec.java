package dev.krypt04mcg.protocol;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.util.*;
import com.google.gson.Gson;

/** File-specific envelope limits, without increasing the chat protocol's limits. */
public final class FileTransferCodec {
    public static final int MAX_FILE_BYTES = 10 * 1024 * 1024;
    public static final int MAX_DATA_CHARS = (MAX_FILE_BYTES * 4 + 2) / 3;
    public static final int MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;
    public static final int MAX_CHUNKS = 2048;
    private final CryptoService crypto = new CryptoService(MAX_ENVELOPE_BYTES);
    private final PacketCodec packets = new PacketCodec(MAX_ENVELOPE_BYTES + 65536);
    private final Gson gson = JsonSupport.prettyGson();

    public String encrypt(String name, byte[] bytes, PublicIdentity receiver, LocalKeyMaterial sender,
                          AeadAlgorithm algorithm) throws Exception {
        if (bytes.length > MAX_FILE_BYTES) throw new IllegalArgumentException("File too large");
        FileData data = new FileData("krypt04mcg:file:v1", name, Base64Url.encode(bytes));
        validate(data);
        var packet = crypto.encryptFor(receiver, sender, sender.kemPublicKey().owner(),
                gson.toJson(data), true, false, algorithm);
        return Base64Url.encode(packets.encode(packet));
    }

    public EncryptedPacket packet(String encoded, String sender, long now) {
        if (encoded.length() > MAX_CHUNKS * OptionalTransferAssembler.CHUNK)
            throw new IllegalArgumentException("Envelope too large");
        var packet = packets.decode(Base64Url.decode(encoded));
        if (packet.type() != PacketType.SIGNED_KEM_MESSAGE || !packet.signed()
                || (packet.flags() & CryptoService.FLAG_SIGNED) == 0
                || (packet.flags() & CryptoService.FLAG_COMPRESSED) != 0
                || !sender.equalsIgnoreCase(packet.sender())
                || packet.timestampMillis() < now - 300000 || packet.timestampMillis() > now + 60000)
            throw new IllegalArgumentException("Invalid file envelope");
        return packet;
    }

    public FileData decrypt(EncryptedPacket packet, LocalKeyMaterial receiver, PublicIdentity sender) throws Exception {
        FileData data = gson.fromJson(crypto.decrypt(packet, receiver, sender), FileData.class);
        validate(data);
        return data;
    }

    private static void validate(FileData data) {
        if (data == null || !"krypt04mcg:file:v1".equals(data.domain) || data.name == null
                || data.name.isBlank() || data.name.length() > 255 || data.data == null
                || data.data.length() > MAX_DATA_CHARS || Base64Url.decode(data.data).length > MAX_FILE_BYTES)
            throw new IllegalArgumentException("Invalid file data");
    }

    public record FileData(String domain, String name, String data) {}
}
