package dev.krypt04mcg.api;

import dev.krypt04mcg.config.Krypt04McgConfig;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/** Stream multiplexer for the ordered tunnel transport. */
public final class KryptStreamRegistry {
    static final String WIRE_CHANNEL = "krypt04mcg:stream:v3";
    private final Map<UUID, KryptSocket> sockets = new ConcurrentHashMap<>();
    private final Map<String, Consumer<KryptSocket>> listeners = new ConcurrentHashMap<>();
    private volatile Krypt04McgConfig config = new Krypt04McgConfig();

    void configure(Krypt04McgConfig config) { this.config = Objects.requireNonNull(config); }

    KryptSocket connect(KryptSession session, String channel) {
        validateChannel(channel);
        UUID id = UUID.randomUUID();
        KryptSocket socket = create(session, channel, id);
        socket.opened();
        return socket;
    }

    private KryptSocket create(KryptSession session, String channel, UUID id) {
        KryptSocket socket = new KryptSocket(session.peer(), channel, id, frame -> {
            session.sendStream(frame.encode());
            if (frame.kind == Kind.CLOSE || frame.kind == Kind.RESET) sockets.remove(id);

        }, config);
        sockets.put(id, socket);
        return socket;
    }

    void register(String channel, Consumer<KryptSocket> listener) {
        validateChannel(channel);
        listeners.put(channel, Objects.requireNonNull(listener));
    }
    void unregister(String channel) { listeners.remove(channel); }

    void receive(KryptSession session, byte[] encoded) {
        Frame frame = Frame.decode(encoded);
        KryptSocket socket = sockets.get(frame.streamId);
        if (frame.kind == Kind.OPEN) {
            if (socket != null) throw new IllegalArgumentException("Duplicate stream OPEN");
            Consumer<KryptSocket> listener = listeners.get(frame.channel);
            socket = create(session, frame.channel, frame.streamId);
            if (listener == null) { socket.protocolError(); return; }
            try { listener.accept(socket); }
            catch (RuntimeException e) { socket.protocolError(); }
            return;
        }
        if (socket == null) return;
        if (!socket.peer().equalsIgnoreCase(session.peer())) throw new IllegalArgumentException("Stream peer mismatch");
        switch (frame.kind) {
            case DATA -> socket.data(frame.sequence, frame.data);
            case CLOSE -> { socket.remoteClose(); sockets.remove(frame.streamId); }
            case RESET -> { socket.remoteReset(); sockets.remove(frame.streamId); }
            default -> { }
        }
    }
    void clear() { sockets.values().forEach(KryptSocket::remoteReset); sockets.clear(); }
    int socketCount() { return sockets.size(); }
    private static void validateChannel(String channel) {
        Objects.requireNonNull(channel, "channel");
        int bytes = channel.getBytes(StandardCharsets.UTF_8).length;
        if (bytes == 0 || bytes > 256) throw new IllegalArgumentException("Stream channel must be 1..256 UTF-8 bytes");
    }

    public enum Kind { OPEN, DATA, CLOSE, RESET }

    public static final class Frame {
        public final Kind kind;
        public final UUID streamId;
        public final long sequence;
        public final String channel;
        public final byte[] data;
        private Frame(Kind kind, UUID streamId, long sequence, String channel, byte[] data) {
            this.kind = kind; this.streamId = streamId; this.sequence = sequence; this.channel = channel; this.data = data;
        }
        public static Frame open(UUID id, String channel) { return new Frame(Kind.OPEN, id, -1, channel, null); }
        public static Frame data(UUID id, long sequence, byte[] data) { return new Frame(Kind.DATA, id, sequence, null, data.clone()); }
        public static Frame close(UUID id) { return new Frame(Kind.CLOSE, id, -1, null, null); }
        public static Frame reset(UUID id) { return new Frame(Kind.RESET, id, -1, null, null); }

        public byte[] encode() {
            try {
                var bytes = new ByteArrayOutputStream();
                var out = new DataOutputStream(bytes);
                out.writeByte(3); out.writeByte(kind.ordinal());
                out.writeLong(streamId.getMostSignificantBits()); out.writeLong(streamId.getLeastSignificantBits());
                if (kind == Kind.OPEN) {
                    byte[] name = channel.getBytes(StandardCharsets.UTF_8);
                    out.writeShort(name.length); out.write(name);
                } else if (kind == Kind.DATA) {
                    out.writeLong(sequence); out.writeInt(data.length); out.write(data);
                }
                return bytes.toByteArray();
            } catch (IOException impossible) { throw new AssertionError(impossible); }
        }

        public static Frame decode(byte[] bytes) {
            try {
                var in = new DataInputStream(new ByteArrayInputStream(bytes));
                if (in.readUnsignedByte() != 3) throw new IOException("version");
                int ordinal = in.readUnsignedByte();
                if (ordinal >= Kind.values().length) throw new IOException("kind");
                Kind kind = Kind.values()[ordinal];
                UUID id = new UUID(in.readLong(), in.readLong());
                Frame frame;
                if (kind == Kind.OPEN) {
                    int size = in.readUnsignedShort();
                    if (size == 0 || size > 256) throw new IOException("channel");
                    byte[] name = in.readNBytes(size);
                    if (name.length != size) throw new IOException("truncated channel");
                    frame = open(id, StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(name)).toString());
                    validateChannel(frame.channel);
                } else if (kind == Kind.DATA) {
                    long sequence = in.readLong();
                    int size = in.readInt();
                    if (sequence < 0 || sequence == Long.MAX_VALUE || size <= 0 || size > KryptSocket.CHUNK_BYTES)
                        throw new IOException("data");
                    byte[] data = in.readNBytes(size);
                    if (data.length != size) throw new IOException("truncated");
                    frame = data(id, sequence, data);
                } else frame = kind == Kind.CLOSE ? close(id) : reset(id);
                if (in.available() != 0) throw new IOException("trailing data");
                return frame;
            } catch (IOException | IllegalArgumentException e) { throw new IllegalArgumentException("Invalid stream frame", e); }
        }

        static UUID peekStreamId(byte[] bytes) {
            if (bytes == null || bytes.length < 18 || (bytes[0] & 0xff) != 3) return null;
            try {
                var in = new DataInputStream(new ByteArrayInputStream(bytes, 2, 16));
                return new UUID(in.readLong(), in.readLong());
            } catch (IOException impossible) { return null; }
        }
    }
}


