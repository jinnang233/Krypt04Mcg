package dev.krypt04mcg.channel;

import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.crypto.XChaCha20Poly1305;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.protocol.ControlPayload;
import dev.krypt04mcg.util.Base64Url;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/** Separate keys for every stream, direction and purpose; counters never appear on data channels. */
public final class ChannelCrypto implements AutoCloseable {
    private final byte[] sendKey, receiveKey, aad;
    private final UUID id;
    private long sent, received;
    public ChannelCrypto(SessionRecord session, UUID id, int slot, String channel, String local, String peer) {
        this.id = id;
        String context = session.sessionId() + "/" + id + "/" + slot + "/" + channel;
        sendKey = derive(session, "data/" + context + "/" + name(local) + "/" + name(peer));
        receiveKey = derive(session, "data/" + context + "/" + name(peer) + "/" + name(local));
        aad = ("krypt04mcg_stream/v1/" + context).getBytes(StandardCharsets.UTF_8);
    }
    public long sent() { return sent; }
    public long received() { return received; }
    public byte[] encrypt(byte[] bytes) throws CryptoException {
        byte[] encrypted = XChaCha20Poly1305.encrypt(sendKey, nonce(sent), aad, bytes);
        sent++; return encrypted;
    }
    public byte[] decrypt(byte[] bytes) throws CryptoException {
        byte[] plain = XChaCha20Poly1305.decrypt(receiveKey, nonce(received), aad, bytes);
        received++; return plain;
    }
    private byte[] nonce(long sequence) throws CryptoException {
        if (sequence == Long.MAX_VALUE) throw new CryptoException("Stream counter exhausted");
        return ByteBuffer.allocate(24).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).putLong(sequence).array();
    }
    public static byte[] authenticate(SessionRecord session, ControlPayload p, String source, String target) {
        byte[] key = derive(session, "control/" + name(source) + "/" + name(target));
        try {
            var mac = new HMac(new SHA256Digest()); mac.init(new KeyParameter(key));
            // OPEN's slot is chosen by the relay after the request; READY authenticates the assigned slot.
            String text = p.kind() + "/" + p.id() + "/" + (p.kind() == ControlPayload.Kind.OPEN ? -1 : p.slot())
                    + "/" + p.channel() + "/" + p.sessionId() + "/" + p.sequence();
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8), tag = new byte[mac.getMacSize()];
            mac.update(bytes, 0, bytes.length); mac.doFinal(tag, 0); return tag;
        } finally { Arrays.fill(key, (byte) 0); }
    }
    public static boolean verify(SessionRecord session, ControlPayload p, String source, String target) {
        return MessageDigest.isEqual(p.body(), authenticate(session, p, source, target));
    }
    private static byte[] derive(SessionRecord session, String info) {
        byte[] secret = Base64Url.decode(session.secret()), key = new byte[32];
        try {
            var hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(secret, Base64Url.decode(session.sessionId()),
                    ("krypt04mcg_stream/v1/" + info).getBytes(StandardCharsets.UTF_8)));
            hkdf.generateBytes(key, 0, key.length); return key;
        } finally { Arrays.fill(secret, (byte) 0); }
    }
    private static String name(String name) { return name.toLowerCase(Locale.ROOT); }
    @Override public void close() { Arrays.fill(sendKey, (byte) 0); Arrays.fill(receiveKey, (byte) 0); }
}
