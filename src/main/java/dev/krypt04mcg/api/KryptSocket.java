package dev.krypt04mcg.api;

import dev.krypt04mcg.config.Krypt04McgConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.Objects;
import java.util.UUID;

/**
 * An ordered, full-duplex stream carried by the authenticated Krypt04Mcg data API.
 * Writes are non-blocking and must be made on the Minecraft client thread. Reads may
 * block and therefore must not be made on that thread.
 */
public final class KryptSocket implements AutoCloseable {
    static final int CHUNK_BYTES = 128 * 1024;
    static final int WINDOW_CHUNKS = 4;
    static final int MAX_BUFFERED_BYTES = 1024 * 1024;

    interface Transport { void send(KryptStreamRegistry.Frame frame); }

    private final String peer, channel;
    private final UUID streamId;
    private final Transport transport;
    private final Krypt04McgConfig config;
    private final Object lock = new Object();
    private final Deque<byte[]> outgoing = new ArrayDeque<>();
    private final Deque<byte[]> incoming = new ArrayDeque<>();
    private final Input input = new Input();
    private final Output output = new Output();
    private long sendSequence, receiveSequence, nextAckSequence;
    private int inFlight, bufferedOutgoing, incomingOffset;
    private boolean localClosing, localClosed, remoteClosed, failed;

    KryptSocket(String peer, String channel, UUID streamId, Transport transport) {
        this(peer, channel, streamId, transport, new Krypt04McgConfig());
    }

    KryptSocket(String peer, String channel, UUID streamId, Transport transport, Krypt04McgConfig config) {
        this.config = Objects.requireNonNull(config);
        this.peer = Objects.requireNonNull(peer);
        this.channel = Objects.requireNonNull(channel);
        this.streamId = Objects.requireNonNull(streamId);
        this.transport = Objects.requireNonNull(transport);
    }

    public String peer() { return peer; }
    public String channel() { return channel; }
    public UUID streamId() { return streamId; }
    public InputStream getInputStream() { return input; }
    public OutputStream getOutputStream() { return output; }
    public boolean isClosed() { synchronized (lock) { return localClosed || failed; } }

    void opened() { transport.send(KryptStreamRegistry.Frame.open(streamId, channel)); }

    void data(long sequence, byte[] bytes) {
        boolean accepted;
        synchronized (lock) {
            accepted = !failed && !remoteClosed && sequence == receiveSequence
                    && bytes.length <= CHUNK_BYTES && queuedIncoming() <= config.socketMaxBufferedMiB() * 1024 * 1024 - bytes.length;
            if (accepted) {
                receiveSequence++;
                incoming.addLast(bytes);
                lock.notifyAll();
            }
        }
        if (accepted) transport.send(KryptStreamRegistry.Frame.ack(streamId, sequence));
        else abort();
    }

    void ack(long sequence) {
        synchronized (lock) {
            if (failed || sequence != nextAckSequence || inFlight == 0) return;
            nextAckSequence++;
            inFlight--;
        }
        pump();
    }

    void remoteClose() {
        synchronized (lock) { remoteClosed = true; lock.notifyAll(); }
    }

    void remoteReset() {
        synchronized (lock) { failed = true; outgoing.clear(); bufferedOutgoing = 0; lock.notifyAll(); }
    }

    private int queuedIncoming() {
        int size = -incomingOffset;
        for (byte[] bytes : incoming) size += bytes.length;
        return size;
    }

    private void pump() {
        while (true) {
            KryptStreamRegistry.Frame next;
            synchronized (lock) {
                if (failed || inFlight >= config.socketWindowChunks()) return;
                byte[] bytes = outgoing.pollFirst();
                if (bytes != null) {
                    bufferedOutgoing -= bytes.length;
                    long sequence = sendSequence++;
                    inFlight++;
                    next = KryptStreamRegistry.Frame.data(streamId, sequence, bytes);
                } else if (localClosing && !localClosed && inFlight == 0) {
                    localClosed = true;
                    next = KryptStreamRegistry.Frame.close(streamId);
                } else return;
            }
            transport.send(next);
        }
    }

    private void abort() {
        boolean notify;
        synchronized (lock) {
            notify = !failed;
            failed = true;
            outgoing.clear();
            bufferedOutgoing = 0;
            lock.notifyAll();
        }
        if (notify) transport.send(KryptStreamRegistry.Frame.reset(streamId));
    }

    @Override public void close() {
        synchronized (lock) { if (localClosing || failed) return; localClosing = true; }
        pump();
    }

    private final class Output extends OutputStream {
        @Override public void write(int value) throws IOException { write(new byte[]{(byte) value}); }
        @Override public void write(byte[] source, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, source.length);
            synchronized (lock) {
                if (localClosing || failed) throw new IOException("KryptSocket output is closed");
                if (length > config.socketMaxBufferedMiB() * 1024 * 1024 - bufferedOutgoing) throw new IOException("KryptSocket backpressure");
                int end = offset + length;
                while (offset < end) {
                    int count = Math.min(CHUNK_BYTES, end - offset);
                    outgoing.addLast(Arrays.copyOfRange(source, offset, offset + count));
                    bufferedOutgoing += count;
                    offset += count;
                }
            }
            pump();
        }
        @Override public void close() { KryptSocket.this.close(); }
    }

    private final class Input extends InputStream {
        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }
        @Override public int read(byte[] target, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, target.length);
            if (length == 0) return 0;
            synchronized (lock) {
                while (incoming.isEmpty() && !remoteClosed && !failed) {
                    try { lock.wait(); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("Interrupted", e); }
                }
                if (failed) throw new IOException("KryptSocket was reset");
                if (incoming.isEmpty()) return -1;
                byte[] head = incoming.peekFirst();
                int count = Math.min(length, head.length - incomingOffset);
                System.arraycopy(head, incomingOffset, target, offset, count);
                incomingOffset += count;
                if (incomingOffset == head.length) { incoming.removeFirst(); incomingOffset = 0; }
                return count;
            }
        }
        @Override public void close() { abort(); }
    }
}
