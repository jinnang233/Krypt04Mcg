package dev.krypt04mcg.protocol;

import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PacketType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;

public final class PacketCodec {
    private static final int MAX_STRING_BYTES = 4096;
    private static final int MAX_BYTES32_FIELD_BYTES = 1024 * 1024;
    private final int maxFieldBytes;

    /**
     * Creates a packet codec with the supplied dependencies and initial state.
     */
    public PacketCodec() { this(MAX_BYTES32_FIELD_BYTES); }

    /**
     * Creates a packet codec with the supplied dependencies and initial state.
     *
     * @param maxFieldBytes the max field bytes supplied to this operation
     */
    public PacketCodec(int maxFieldBytes) {
        if (maxFieldBytes < 1 || maxFieldBytes > 17 * 1024 * 1024) {
            throw new IllegalArgumentException("Invalid packet field limit");
        }
        this.maxFieldBytes = maxFieldBytes;
    }

    /**
     * Serializes the validated version-specific packet layout with explicit field lengths and fixed-width
     * metadata. Encoding produces canonical wire bytes but does not encrypt, authenticate or establish
     * trust in the fields.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @return the resulting array produced by this operation
     */
    public byte[] encode(EncryptedPacket packet) {
        validateLayout(packet);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(packet.protocolVersion());
            out.writeByte(packet.type().id());
            out.writeByte(packet.flags());
            writeString(out, packet.sender());
            writeString(out, packet.receiver());
            out.writeLong(packet.timestampMillis());
            writeFixed(out, packet.messageId(), 16, "messageId");
            if (isSessionV4(packet.protocolVersion(), packet.type())) {
                writeString(out, packet.sessionId());
                out.writeLong(packet.sequence());
            }
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION) {
                out.writeShort(packet.aadFragmentIndex());
                out.writeShort(packet.aadFragmentTotal());
            }
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION || usesKem(packet.type())) {
                writeString(out, packet.algorithms().kem());
            }
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION || isSigned(packet.flags())) {
                writeString(out, packet.algorithms().signature());
            }
            writeString(out, packet.algorithms().aead());
            writeString(out, packet.algorithms().hkdf());
            writeBytes16(out, packet.nonce());
            writeBytes32(out, packet.kemCiphertext());
            writeBytes32(out, packet.ciphertext());
            if (!isSessionV4(packet.protocolVersion(), packet.type())) {
                writeBytes32(out, packet.signature());
            }
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected packet encoding failure", e);
        }
    }

    /**
     * Parses a bounded versioned packet, validates lengths and field combinations, and rejects truncation
     * or trailing bytes. Decoded sender/routing fields are claims until the transport and cryptographic
     * receive paths validate them; parsing is not signature verification.
     *
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     */
    public EncryptedPacket decode(byte[] encoded) {
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
            byte version = in.readByte();
            if (version != EncryptedPacket.LEGACY_VERSION && version != EncryptedPacket.PREVIOUS_VERSION
                    && version != EncryptedPacket.COMPACT_VERSION && version != EncryptedPacket.VERSION) {
                throw new IOException("Unsupported protocol version: " + Byte.toUnsignedInt(version));
            }
            PacketType type = PacketType.fromId(in.readUnsignedByte());
            byte flags = in.readByte();
            if (isSessionV4(version, type) && isSigned(flags)) {
                throw new IOException("Session messages cannot be signed");
            }
            String sender = readString(in);
            String receiver = readString(in);
            long timestamp = in.readLong();
            byte[] messageId = in.readNBytes(16);
            if (messageId.length != 16) {
                throw new IOException("Truncated message id");
            }
            String sessionId = isSessionV4(version, type) ? readString(in) : "";
            long sequence = isSessionV4(version, type) ? in.readLong() : 0;
            short aadFragmentIndex = 0;
            short aadFragmentTotal = 1;
            if (version < EncryptedPacket.COMPACT_VERSION) {
                aadFragmentIndex = in.readShort();
                aadFragmentTotal = in.readShort();
            }
            String kem = version < EncryptedPacket.COMPACT_VERSION || usesKem(type) ? readString(in) : "NONE";
            String signatureAlgorithm = version < EncryptedPacket.COMPACT_VERSION || isSigned(flags) ? readString(in) : "NONE";
            AlgorithmSuite algorithms = new AlgorithmSuite(kem, signatureAlgorithm, readString(in), readString(in));
            byte[] nonce = readBytes16(in);
            byte[] kemCiphertext = readBytes32(in);
            byte[] ciphertext = readBytes32(in);
            byte[] signature = isSessionV4(version, type) ? new byte[0] : readBytes32(in);
            if (in.available() != 0) {
                throw new IOException("Trailing packet bytes: " + in.available());
            }
            var packet = new EncryptedPacket(version, type, flags, sender, receiver, timestamp, messageId,
                    aadFragmentIndex, aadFragmentTotal, algorithms, nonce, kemCiphertext, ciphertext, signature, sessionId, sequence);
            validateLayout(packet);
            return packet;
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid Krypt04Mcg packet", e);
        }
    }

    /**
     * Serializes canonical authenticated metadata for the packet version, including the session
     * ID/sequence when the layout carries them. AEAD binds exactly these bytes; legacy field coverage
     * differs from compact versions and must not be inferred from object equality.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @return the resulting array produced by this operation
     */
    public byte[] aadFor(EncryptedPacket packet) {
        validateLayout(packet);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(packet.protocolVersion());
            out.writeByte(packet.type().id());
            out.writeByte(packet.flags());
            writeString(out, packet.sender());
            writeString(out, packet.receiver());
            if (packet.protocolVersion() >= EncryptedPacket.COMPACT_VERSION) {
                out.writeLong(packet.timestampMillis());
            }
            writeFixed(out, packet.messageId(), 16, "messageId");
            if (isSessionV4(packet.protocolVersion(), packet.type())) {
                writeString(out, packet.sessionId());
                out.writeLong(packet.sequence());
            }
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION) {
                out.writeShort(packet.aadFragmentIndex());
                out.writeShort(packet.aadFragmentTotal());
            }
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION || usesKem(packet.type())) {
                writeString(out, packet.algorithms().kem());
            }
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION || isSigned(packet.flags())) {
                writeString(out, packet.algorithms().signature());
            }
            writeString(out, packet.algorithms().aead());
            if (packet.protocolVersion() >= EncryptedPacket.PREVIOUS_VERSION) {
                writeString(out, packet.algorithms().hkdf());
            }
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected AAD encoding failure", e);
        }
    }

    /**
     * Builds canonical signature bytes from AAD, version-dependent timestamp coverage, nonce, KEM
     * encapsulation and ciphertext. The signature field itself is omitted so signing and verification
     * reconstruct the same input without circular dependence.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @return the resulting array produced by this operation
     */
    public byte[] signatureInput(EncryptedPacket packet) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write(aadFor(packet));
            if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION) {
                out.writeLong(packet.timestampMillis());
            }
            writeBytes16(out, packet.nonce());
            writeBytes32(out, packet.kemCiphertext());
            writeBytes32(out, packet.ciphertext());
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected signature input encoding failure", e);
        }
    }

    /**
     * Returns a value with the supplied out signature while retaining the other recorded fields.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @return the result described above
     */
    public EncryptedPacket withoutSignature(EncryptedPacket packet) {
        return new EncryptedPacket(packet.protocolVersion(), packet.type(), packet.flags(), packet.sender(),
                packet.receiver(), packet.timestampMillis(), packet.messageId(), packet.aadFragmentIndex(),
                packet.aadFragmentTotal(), packet.algorithms(), packet.nonce(), packet.kemCiphertext(),
                packet.ciphertext(), new byte[0], packet.sessionId(), packet.sequence());
    }

    /**
     * Rejects fields that the selected packet version/type cannot carry or authenticate rather than
     * silently dropping them during serialization. Layout validity is distinct from trusted sender
     * identity, freshness and replay acceptance.
     *
     * @param packet the packet being serialized, authenticated or processed
     */
    public static void validateLayout(EncryptedPacket packet) {
        if (packet == null || packet.type() == null || packet.algorithms() == null)
            throw new IllegalArgumentException("Missing packet layout");
        byte version = packet.protocolVersion();
        if (version < EncryptedPacket.LEGACY_VERSION || version > EncryptedPacket.VERSION)
            throw new IllegalArgumentException("Unsupported packet version");
        boolean session = packet.type() == PacketType.SESSION_MESSAGE;
        if (session) {
            if (version != EncryptedPacket.VERSION || isSigned(packet.flags()) || packet.signed()
                    || !"NONE".equals(packet.algorithms().signature()) || !"NONE".equals(packet.algorithms().kem())
                    || packet.kemCiphertext() == null || packet.kemCiphertext().length != 0)
                throw new IllegalArgumentException("Session packets cannot carry KEM or signature fields");
        } else if (!"".equals(packet.sessionId()) || packet.sequence() != 0) {
            throw new IllegalArgumentException("Only session packets carry session metadata");
        }
        if (version >= EncryptedPacket.COMPACT_VERSION) {
            if (packet.aadFragmentIndex() != 0 || packet.aadFragmentTotal() != 1)
                throw new IllegalArgumentException("Compact packets cannot carry fragment metadata");
            if (!isSigned(packet.flags()) && (!"NONE".equals(packet.algorithms().signature()) || packet.signed()))
                throw new IllegalArgumentException("Unsigned packets cannot carry signature fields");
        }
    }

    /**
     * Writes string to the output used by the versioned encrypted-packet codec.
     *
     * @param out the out supplied to this operation
     * @param value the value supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void writeString(DataOutputStream out, String value) throws IOException {
        if (value == null || value.length() > MAX_STRING_BYTES) {
            throw new IOException("String is missing or too long");
        }
        byte[] encoded;
        try {
            ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            encoded = new byte[buffer.remaining()];
            buffer.get(encoded);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Protocol string contains invalid Unicode", e);
        }
        if (encoded.length > MAX_STRING_BYTES) {
            throw new IOException("String too long");
        }
        out.writeShort(encoded.length);
        out.write(encoded);
    }

    /**
     * Reads a bounded length-prefixed UTF-8 field. The client codec uses strict malformed-input reporting
     * because these strings are reconstructed into AAD and signature input; callers must not assume
     * successful parsing establishes authentication.
     *
     * @param in the in supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static String readString(DataInputStream in) throws IOException {
        int length = in.readUnsignedShort();
        if (length > MAX_STRING_BYTES) {
            throw new IOException("String field too long: " + length);
        }
        // Reject invalid encodings: AAD and signatures are reconstructed from these strings.
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(readExact(in, length, "string"))).toString();
    }

    /**
     * Writes bytes16 to the output used by the versioned encrypted-packet codec.
     *
     * @param out the out supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void writeBytes16(DataOutputStream out, byte[] bytes) throws IOException {
        if (bytes == null) {
            out.writeShort(0);
            return;
        }
        if (bytes.length > 65535) {
            throw new IOException("Field too long for short length");
        }
        out.writeShort(bytes.length);
        out.write(bytes);
    }

    /**
     * Reads bytes16 from the input used by the versioned encrypted-packet codec.
     *
     * @param in the in supplied to this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static byte[] readBytes16(DataInputStream in) throws IOException {
        int length = in.readUnsignedShort();
        return readExact(in, length, "bytes16");
    }

    /**
     * Writes bytes32 to the output used by the versioned encrypted-packet codec.
     *
     * @param out the out supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void writeBytes32(DataOutputStream out, byte[] bytes) throws IOException {
        if (bytes == null) {
            out.writeInt(0);
            return;
        }
        if (bytes.length > maxFieldBytes) {
            throw new IOException("Field too long: " + bytes.length);
        }
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    /**
     * Reads bytes32 from the input used by the versioned encrypted-packet codec.
     *
     * @param in the in supplied to this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private byte[] readBytes32(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0) {
            throw new IOException("Negative length");
        }
        if (length > maxFieldBytes) {
            throw new IOException("Field too long: " + length);
        }
        return readExact(in, length, "bytes32");
    }

    /**
     * Writes fixed to the output used by the versioned encrypted-packet codec.
     *
     * @param out the out supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @param length the requested or declared byte count
     * @param field the field supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void writeFixed(DataOutputStream out, byte[] bytes, int length, String field) throws IOException {
        if (bytes == null || bytes.length != length) {
            throw new IOException(field + " must be " + length + " bytes, got " + Arrays.toString(bytes));
        }
        out.write(bytes);
    }

    /**
     * Reads the declared bounded field length and rejects a short read instead of accepting a truncated
     * authenticated representation.
     *
     * @param in the in supplied to this operation
     * @param length the requested or declared byte count
     * @param field the field supplied to this operation
     * @return the resulting array produced by this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static byte[] readExact(DataInputStream in, int length, String field) throws IOException {
        byte[] bytes = in.readNBytes(length);
        if (bytes.length != length) {
            throw new IOException("Truncated " + field);
        }
        return bytes;
    }

    /**
     * Reports whether session v4 holds for the versioned encrypted-packet codec.
     *
     * @param version the version supplied to this operation
     * @param type the type supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean isSessionV4(byte version, PacketType type) {
        return version >= EncryptedPacket.VERSION && type == PacketType.SESSION_MESSAGE;
    }

    /**
     * Performs the uses kem operation for the versioned encrypted-packet codec.
     *
     * @param type the type supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean usesKem(PacketType type) {
        return type != PacketType.SESSION_MESSAGE;
    }

    /**
     * Reports whether signed holds for the versioned encrypted-packet codec.
     *
     * @param flags the flags supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean isSigned(byte flags) {
        return (flags & dev.krypt04mcg.crypto.CryptoService.FLAG_SIGNED) != 0;
    }
}
