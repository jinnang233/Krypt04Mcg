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
    private boolean closed;
    /**
     * Derives separate send and receive keys from the session secret and a context containing session ID,
     * stream UUID, assigned slot, business channel and ordered endpoint names. Data keys and control keys
     * use different domain labels; canonical endpoint order reverses with direction. Equal normalized
     * endpoints are rejected. The stream UUID also participates in nonce construction, while per-direction
     * record counters begin at zero.
     *
     * @param session the session supplied to this operation
     * @param id the id supplied to this operation
     * @param slot the slot supplied to this operation
     * @param channel the business or transport channel identifier
     * @param local the local supplied to this operation
     * @param peer the peer identifier associated with this operation
     */
    public ChannelCrypto(SessionRecord session, UUID id, int slot, String channel, String local, String peer) {
        if (name(local).equals(name(peer)))
            throw new IllegalArgumentException("Stream endpoints must have distinct identities");
        this.id = id;
        String context = session.sessionId() + "/" + id + "/" + slot + "/" + channel;
        sendKey = derive(session, "data/" + context + "/" + name(local) + "/" + name(peer));
        receiveKey = derive(session, "data/" + context + "/" + name(peer) + "/" + name(local));
        aad = ("krypt04mcg_stream/v1/" + context).getBytes(StandardCharsets.UTF_8);
    }
    /**
     * Returns the recorded sent for the direction-separated stream cryptography.
     *
     * @return the result described above
     */
    public synchronized long sent() { return sent; }
    /**
     * Returns the recorded received for the direction-separated stream cryptography.
     *
     * @return the result described above
     */
    public synchronized long received() { return received; }
    /**
     * Encrypts the next ordered stream record under the direction-specific XChaCha20-Poly1305 key and
     * context AAD. The implicit send counter advances only after successful encryption; both peers must
     * preserve record order because data-channel records carry no explicit counter.
     *
     * @param bytes the bytes supplied to this operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public synchronized byte[] encrypt(byte[] bytes) throws CryptoException {
        if (closed) throw new CryptoException("Stream crypto closed");
        byte[] encrypted = XChaCha20Poly1305.encrypt(sendKey, nonce(sent), aad, bytes);
        sent++; return encrypted;
    }
    /**
     * Authenticates the next ordered stream record using the expected implicit receive counter. The
     * counter advances only after successful tag verification. Reordered, omitted or duplicated records
     * cannot be transparently recovered by this ordered-stream construction.
     *
     * @param bytes the bytes supplied to this operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public synchronized byte[] decrypt(byte[] bytes) throws CryptoException {
        if (closed) throw new CryptoException("Stream crypto closed");
        byte[] plain = XChaCha20Poly1305.decrypt(receiveKey, nonce(received), aad, bytes);
        received++; return plain;
    }
    /**
     * Builds the 24-byte XChaCha nonce from the stream UUID and ordered record sequence. Counter
     * exhaustion is rejected before reuse. Direction-separated keys keep the same numerical sequence in
     * opposite directions in distinct key/nonce domains.
     *
     * @param sequence the record or control sequence in the relevant replay domain
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private byte[] nonce(long sequence) throws CryptoException {
        if (sequence == Long.MAX_VALUE) throw new CryptoException("Stream counter exhausted");
        return ByteBuffer.allocate(24).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).putLong(sequence).array();
    }
    /**
     * Computes HMAC-SHA256 over canonical control kind, stream ID, channel, session ID and sequence using
     * a direction-specific control key. OPEN uses slot -1 because assignment happens at the relay; READY
     * authenticates the assigned slot. Control identity and replay counters must be validated by the
     * caller.
     *
     * @param session the session supplied to this operation
     * @param p the p supplied to this operation
     * @param source the source supplied to this operation
     * @param target the target supplied to this operation
     * @return the resulting array produced by this operation
     */
    public static byte[] authenticate(SessionRecord session, ControlPayload p, String source, String target) {
        byte[] key = derive(session, "control/" + name(source) + "/" + name(target));
        try {
            /*
             * Uses Bouncy Castle HMAC-SHA256 for keyed control-message authentication. The key is
             * purpose/direction separated, and the canonical control fields must match on both endpoints; sequence
             * admission is still a separate replay check.
             */
            var mac = new HMac(new SHA256Digest()); mac.init(new KeyParameter(key));
            // OPEN's slot is chosen by the relay after the request; READY authenticates the assigned slot.
            String text = p.kind() + "/" + p.id() + "/" + (p.kind() == ControlPayload.Kind.OPEN ? -1 : p.slot())
                    + "/" + p.channel() + "/" + p.sessionId() + "/" + p.sequence();
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8), tag = new byte[mac.getMacSize()];
            mac.update(bytes, 0, bytes.length); mac.doFinal(tag, 0); return tag;
        /*
         * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
         * immutable Strings, returned copies and provider/native key objects may retain other copies.
         */
        } finally { Arrays.fill(key, (byte) 0); }
    }
    /**
     * Recomputes the control HMAC and compares it with MessageDigest.isEqual rather than String equality.
     * This verifies the tag under the supplied session and endpoint context; replay/order validation is
     * performed by session services.
     *
     * @param session the session supplied to this operation
     * @param p the p supplied to this operation
     * @param source the source supplied to this operation
     * @param target the target supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public static boolean verify(SessionRecord session, ControlPayload p, String source, String target) {
        /*
         * Compares digest/tag bytes with the JDK authentication-oriented byte comparison rather than
         * converting them to Strings. Equality still depends on the supplied key/context and does not replace
         * identity or replay checks.
         */
        return MessageDigest.isEqual(p.body(), authenticate(session, p, source, target));
    }
    /**
     * Derives a 32-byte key with BC HKDF-SHA256 from the decoded session secret, session-ID salt and
     * versioned purpose/direction info. Stream, direction, data and control contexts remain distinct. The
     * temporary secret copy is overwritten, while the returned key remains sensitive.
     *
     * @param session the session supplied to this operation
     * @param info the HKDF domain/context information
     * @return the resulting array produced by this operation
     */
    private static byte[] derive(SessionRecord session, String info) {
        byte[] secret = Base64Url.decode(session.secret()), key = new byte[32];
        try {
            /*
             * Delegates RFC 5869 extract-and-expand to Bouncy Castle with SHA-256. Input secret entropy, salt and
             * purpose-specific info have distinct roles; HKDF does not authenticate those context fields by
             * itself.
             */
            var hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(secret, Base64Url.decode(session.sessionId()),
                    ("krypt04mcg_stream/v1/" + info).getBytes(StandardCharsets.UTF_8)));
            hkdf.generateBytes(key, 0, key.length); return key;
        /*
         * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
         * immutable Strings, returned copies and provider/native key objects may retain other copies.
         */
        } finally { Arrays.fill(secret, (byte) 0); }
    }
    /**
     * Returns the name value used by the direction-separated stream cryptography.
     *
     * @param name the name supplied to this operation
     * @return the result described above
     */
    private static String name(String name) { return name.toLowerCase(Locale.ROOT); }
    /**
     * Marks the stream cryptographic state closed and overwrites both direction keys. Later
     * encrypt/decrypt operations fail. Buffer overwriting does not guarantee erasure of provider
     * temporaries, immutable session strings or previously returned records.
     */
    @Override public synchronized void close() {
        closed = true;
        /*
         * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
         * immutable Strings, returned copies and provider/native key objects may retain other copies.
         */
        /*
         * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
         * immutable Strings, returned copies and provider/native key objects may retain other copies.
         */
        Arrays.fill(sendKey, (byte) 0); Arrays.fill(receiveKey, (byte) 0);
    }
}
