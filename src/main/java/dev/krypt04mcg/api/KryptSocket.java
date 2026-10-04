package dev.krypt04mcg.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Bounded duplex byte stream. Reads may block; never read on the Minecraft client thread. */
public final class KryptSocket implements AutoCloseable {
    public static final int MAX_BUFFERED_BYTES = 1024 * 1024;
    private final String peer, channel;
    private final UUID streamId;
    private final ByteQueue incoming = new ByteQueue(), outgoing = new ByteQueue();
    private boolean closing, endSent, remoteEnded;
    private IOException failure;
    private final InputStream input = new Input();
    private final OutputStream output = new Output();

    /** Internal channel transport bridge. */
    public KryptSocket(String peer, String channel, UUID streamId) {
        this.peer = Objects.requireNonNull(peer); this.channel = Objects.requireNonNull(channel);
        this.streamId = Objects.requireNonNull(streamId);
    }
    public String peer() { return peer; }
    public String channel() { return channel; }
    public UUID streamId() { return streamId; }
    public InputStream getInputStream() { return input; }
    public OutputStream getOutputStream() { return output; }
    public synchronized boolean isClosed() { return failure != null || (endSent && remoteEnded); }
    public synchronized boolean isFailed() { return failure != null; }
    public synchronized boolean outputEnded() { return endSent; }
    /** Current output capacity; producers must serialize capacity checks and writes with other writers. */
    public synchronized int writableBytes() { return closing || failure != null ? 0 : MAX_BUFFERED_BYTES - outgoing.size; }

    /** Internal: takes bytes in stream order using Minecraft's record size limit. */
    public synchronized byte[] poll(int maximum) {
        if (maximum <= 0) throw new IllegalArgumentException("Positive read size required");
        if (failure != null || outgoing.isEmpty()) return null;
        byte[] bytes = new byte[Math.min(maximum, outgoing.size)];
        outgoing.read(bytes, 0, bytes.length);
        return bytes;
    }
    public synchronized boolean needsEnd() { return closing && !endSent && outgoing.isEmpty() && failure == null; }
    public synchronized void endSent() { endSent = true; }
    public synchronized void remoteEnd() { remoteEnded = true; notifyAll(); }
    public synchronized void accept(byte[] bytes) throws IOException {
        if (failure != null || remoteEnded || bytes.length > MAX_BUFFERED_BYTES - incoming.size)
            throw new IOException("Stream receive buffer exhausted or closed");
        if (bytes.length != 0) { incoming.write(bytes, 0, bytes.length); notifyAll(); }
    }
    public synchronized void fail(String reason) {
        if (failure == null) failure = new IOException(reason);
        incoming.clear(); outgoing.clear(); notifyAll();
    }
    /** Half-closes output after queued bytes; input remains readable until authenticated EOF. */
    @Override public synchronized void close() { closing = true; }
    private final class Output extends OutputStream {
        @Override public void write(int value) throws IOException { write(new byte[]{(byte) value}); }
        @Override public void write(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            synchronized (KryptSocket.this) {
                if (failure != null) throw failure;
                if (closing) throw new IOException("Stream output closed");
                if (length > MAX_BUFFERED_BYTES - outgoing.size) throw new IOException("Stream backpressure");
                if (length != 0) outgoing.write(bytes, offset, length);
            }
        }
        @Override public void close() { KryptSocket.this.close(); }
    }
    private final class Input extends InputStream {
        @Override public int read() throws IOException {
            byte[] one = new byte[1]; return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
        }
        @Override public int read(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            if (length == 0) return 0;
            synchronized (KryptSocket.this) {
                while (incoming.isEmpty() && !remoteEnded && failure == null) {
                    try { KryptSocket.this.wait(); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("Interrupted", e); }
                }
                if (failure != null) throw failure;
                if (incoming.isEmpty()) return -1;
                int count = Math.min(length, incoming.size);
                incoming.read(bytes, offset, count);
                return count;
            }
        }
        @Override public void close() { fail("Stream input closed"); }
    }
    /** Byte-bounded ring queues coalesce tiny writes without retaining a million array objects. */
    private static final class ByteQueue {
        private byte[] bytes = new byte[0];
        private int head, size;
        boolean isEmpty() { return size == 0; }
        void write(byte[] source, int offset, int length) {
            if (length == 0) return;
            if (size + length > bytes.length) {
                byte[] grown = new byte[Math.min(MAX_BUFFERED_BYTES, Math.max(4096, Math.max(size + length, bytes.length * 2)))];
                int first = Math.min(size, bytes.length - head);
                System.arraycopy(bytes, head, grown, 0, first);
                System.arraycopy(bytes, 0, grown, first, size - first);
                Arrays.fill(bytes, (byte) 0); bytes = grown; head = 0;
            }
            int tail = (head + size) % bytes.length;
            int first = Math.min(length, bytes.length - tail);
            System.arraycopy(source, offset, bytes, tail, first);
            System.arraycopy(source, offset + first, bytes, 0, length - first);
            size += length;
        }
        void read(byte[] target, int offset, int length) {
            int first = Math.min(length, bytes.length - head);
            System.arraycopy(bytes, head, target, offset, first);
            System.arraycopy(bytes, 0, target, offset + first, length - first);
            Arrays.fill(bytes, head, head + first, (byte) 0);
            Arrays.fill(bytes, 0, length - first, (byte) 0);
            head = (head + length) % bytes.length; size -= length;
            if (size == 0) head = 0;
        }
        void clear() { Arrays.fill(bytes, (byte) 0); bytes = new byte[0]; head = size = 0; }
    }

}
