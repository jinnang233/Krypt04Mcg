package dev.krypt04mcg.api;

import dev.krypt04mcg.api.TransferResult.Status;
import dev.krypt04mcg.config.Krypt04McgConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;

/** Package-private stream multiplexer over the reliable encrypted data channel. */
final class KryptStreamRegistry {
    static final String WIRE_CHANNEL = "krypt04mcg:stream:v1";
    private static final int VERSION = 1;
    private final Map<UUID, KryptSocket> sockets = new HashMap<>();
    private final Map<String, Consumer<KryptSocket>> listeners = new HashMap<>();
    private boolean receiverInstalled;
    private Krypt04McgConfig config = new Krypt04McgConfig();

    void configure(Krypt04McgConfig config) { this.config = Objects.requireNonNull(config); }

    KryptSocket connect(KryptSession session, String channel) {
        validateChannel(channel);
        installReceiver();
        UUID id = UUID.randomUUID();
        KryptSocket socket = new KryptSocket(session.peer(), channel, id, frame -> send(session, frame, id), config);
        sockets.put(id, socket);
        socket.opened();
        return socket;
    }

    void register(String channel, Consumer<KryptSocket> listener) {
        validateChannel(channel);
        installReceiver();
        listeners.put(channel, Objects.requireNonNull(listener, "receiver"));
    }

    void unregister(String channel) { listeners.remove(channel); }

    private void installReceiver() {
        if (receiverInstalled) return;
        Krypt04McgApi.registerReceiver(WIRE_CHANNEL, this::receive);
        receiverInstalled = true;
    }

    private void receive(String sender, byte[] encoded) {
        final Frame frame;
        try { frame = Frame.decode(encoded); }
        catch (RuntimeException e) { return; }
        KryptSocket socket = sockets.get(frame.streamId);
        if (frame.kind == Kind.OPEN) {
            if (socket != null) return;
            Consumer<KryptSocket> listener = listeners.get(frame.channel);
            KryptSession session = Krypt04McgApi.connect(sender);
            if (listener == null) { send(session, Frame.reset(frame.streamId), frame.streamId); return; }
            socket = new KryptSocket(sender, frame.channel, frame.streamId, reply -> send(session, reply, frame.streamId), config);
            sockets.put(frame.streamId, socket);
            try { listener.accept(socket); }
            catch (RuntimeException e) { socket.close(); throw e; }
            return;
        }
        if (socket == null || !socket.peer().equalsIgnoreCase(sender)) return;
        switch (frame.kind) {
            case DATA -> socket.data(frame.sequence, frame.data);
            case ACK -> socket.ack(frame.sequence);
            case CLOSE -> { socket.remoteClose(); sockets.remove(frame.streamId); }
            case RESET -> { socket.remoteReset(); sockets.remove(frame.streamId); }
            default -> { }
        }
    }

    private void send(KryptSession session, Frame frame, UUID id) {
        session.send(WIRE_CHANNEL, frame.encode()).whenComplete(result -> {
            if (result.status() != Status.DELIVERED) {
                KryptSocket socket = sockets.remove(id);
                if (socket != null) socket.remoteReset();
            } else if (frame.kind == Kind.CLOSE || frame.kind == Kind.RESET) sockets.remove(id);
        });
    }

    private static void validateChannel(String channel) {
        Objects.requireNonNull(channel, "channel");
        int bytes = channel.getBytes(StandardCharsets.UTF_8).length;
        if (bytes == 0 || bytes > 256) throw new IllegalArgumentException("Stream channel must be 1..256 UTF-8 bytes");
    }

    enum Kind { OPEN, DATA, ACK, CLOSE, RESET }

    static final class Frame {
        final Kind kind;
        final UUID streamId;
        final long sequence;
        final String channel;
        final byte[] data;
        private Frame(Kind kind, UUID streamId, long sequence, String channel, byte[] data) {
            this.kind = kind; this.streamId = streamId; this.sequence = sequence; this.channel = channel; this.data = data;
        }
        static Frame open(UUID id, String channel) { return new Frame(Kind.OPEN, id, -1, channel, null); }
        static Frame data(UUID id, long sequence, byte[] data) { return new Frame(Kind.DATA, id, sequence, null, data.clone()); }
        static Frame ack(UUID id, long sequence) { return new Frame(Kind.ACK, id, sequence, null, null); }
        static Frame close(UUID id) { return new Frame(Kind.CLOSE, id, -1, null, null); }
        static Frame reset(UUID id) { return new Frame(Kind.RESET, id, -1, null, null); }

        byte[] encode() {
            try {
                var bytes = new ByteArrayOutputStream();
                var out = new DataOutputStream(bytes);
                out.writeByte(VERSION); out.writeByte(kind.ordinal());
                out.writeLong(streamId.getMostSignificantBits()); out.writeLong(streamId.getLeastSignificantBits());
                if (kind == Kind.OPEN) {
                    byte[] name = channel.getBytes(StandardCharsets.UTF_8);
                    out.writeShort(name.length); out.write(name);
                } else if (kind == Kind.DATA) {
                    out.writeLong(sequence); out.writeInt(data.length); out.write(data);
                } else if (kind == Kind.ACK) out.writeLong(sequence);
                return bytes.toByteArray();
            } catch (IOException impossible) { throw new AssertionError(impossible); }
        }

        static Frame decode(byte[] bytes) {
            try {
                var in = new DataInputStream(new ByteArrayInputStream(bytes));
                if (in.readUnsignedByte() != VERSION) throw new IOException("version");
                int ordinal = in.readUnsignedByte();
                if (ordinal >= Kind.values().length) throw new IOException("kind");
                Kind kind = Kind.values()[ordinal];
                UUID id = new UUID(in.readLong(), in.readLong());
                Frame frame;
                if (kind == Kind.OPEN) {
                    int size = in.readUnsignedShort();
                    if (size == 0 || size > 256) throw new IOException("channel");
                    frame = open(id, new String(in.readNBytes(size), StandardCharsets.UTF_8));
                    validateChannel(frame.channel);
                } else if (kind == Kind.DATA) {
                    long sequence = in.readLong();
                    int size = in.readInt();
                    if (sequence < 0 || size < 0 || size > KryptSocket.CHUNK_BYTES) throw new IOException("data");
                    byte[] data = in.readNBytes(size);
                    if (data.length != size) throw new IOException("truncated");
                    frame = data(id, sequence, data);
                } else if (kind == Kind.ACK) {
                    long sequence = in.readLong();
                    if (sequence < 0) throw new IOException("ack");
                    frame = ack(id, sequence);
                } else frame = kind == Kind.CLOSE ? close(id) : reset(id);
                if (in.available() != 0) throw new IOException("trailing data");
                return frame;
            } catch (IOException | IllegalArgumentException e) { throw new IllegalArgumentException("Invalid stream frame", e); }
        }
    }
}
