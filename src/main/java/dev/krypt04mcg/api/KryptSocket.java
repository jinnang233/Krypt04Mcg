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

    /**
     * Creates a krypt socket with the supplied dependencies and initial state.
     *
     * @param peer the peer identifier associated with this operation
     * @param channel the business or transport channel identifier
     * @param streamId the stream id supplied to this operation
     */
    public KryptSocket(String peer, String channel, UUID streamId) {
        this.peer = Objects.requireNonNull(peer); this.channel = Objects.requireNonNull(channel);
        this.streamId = Objects.requireNonNull(streamId);
    }
    /**
     * Returns the peer value used by the bounded encrypted byte-stream socket.
     *
     * @return the result described above
     */
    public String peer() { return peer; }
    /**
     * Returns the channel value used by the bounded encrypted byte-stream socket.
     *
     * @return the result described above
     */
    public String channel() { return channel; }
    /**
     * Returns the stream id value used by the bounded encrypted byte-stream socket.
     *
     * @return the result described above
     */
    public UUID streamId() { return streamId; }
    /**
     * Returns the input stream exposed by the bounded encrypted byte-stream socket.
     *
     * @return the result described above
     */
    public InputStream getInputStream() { return input; }
    /**
     * Returns the output stream exposed by the bounded encrypted byte-stream socket.
     *
     * @return the result described above
     */
    public OutputStream getOutputStream() { return output; }
    /**
     * Reports whether closed holds for the bounded encrypted byte-stream socket.
     *
     * @return whether the condition or operation described above succeeds
     */
    public synchronized boolean isClosed() { return failure != null || (endSent && remoteEnded); }
    /**
     * Reports whether failed holds for the bounded encrypted byte-stream socket.
     *
     * @return whether the condition or operation described above succeeds
     */
    public synchronized boolean isFailed() { return failure != null; }
    /**
     * Returns the recorded end sent for the bounded encrypted byte-stream socket.
     *
     * @return whether the condition or operation described above succeeds
     */
    public synchronized boolean outputEnded() { return endSent; }
    /**
     * Reports remaining local output-buffer capacity for nonblocking backpressure. Capacity is not a
     * remote-delivery acknowledgement and becomes zero when closing or failed.
     *
     * @return the result described above
     */
    public synchronized int writableBytes() { return closing || failure != null ? 0 : MAX_BUFFERED_BYTES - outgoing.size; }

    /**
     * Removes at most the requested number of queued output bytes for the client-thread encrypted-record
     * pump. Application message boundaries are not preserved by this byte-stream extraction.
     *
     * @param maximum the maximum supplied to this operation
     * @return the resulting array produced by this operation
     */
    public synchronized byte[] poll(int maximum) {
        if (maximum <= 0) throw new IllegalArgumentException("Positive read size required");
        if (failure != null || outgoing.isEmpty()) return null;
        byte[] bytes = new byte[Math.min(maximum, outgoing.size)];
        outgoing.read(bytes, 0, bytes.length);
        return bytes;
    }
    /**
     * Performs the needs end operation for the bounded encrypted byte-stream socket.
     *
     * @return whether the condition or operation described above succeeds
     */
    public synchronized boolean needsEnd() { return closing && !endSent && outgoing.isEmpty() && failure == null; }
    /**
     * Performs the end sent operation for the bounded encrypted byte-stream socket.
     */
    public synchronized void endSent() { endSent = true; }
    /**
     * Performs the remote end operation for the bounded encrypted byte-stream socket.
     */
    public synchronized void remoteEnd() { remoteEnded = true; notifyAll(); }
    /**
     * Appends an authenticated incoming stream portion only if the socket remains valid, remote EOF has
     * not arrived and the receive buffer has capacity. Overflow/failure retires the stream rather than
     * accepting partial unauthenticated application data.
     *
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void accept(byte[] bytes) throws IOException {
        if (failure != null || remoteEnded || bytes.length > MAX_BUFFERED_BYTES - incoming.size)
            throw new IOException("Stream receive buffer exhausted or closed");
        if (bytes.length != 0) { incoming.write(bytes, 0, bytes.length); notifyAll(); }
    }
    /**
     * Records a stream failure and clears buffered state as implemented so blocked readers/writers cannot
     * continue using a failed channel.
     *
     * @param reason the reason supplied to this operation
     */
    public synchronized void fail(String reason) {
        if (failure == null) failure = new IOException(reason);
        incoming.clear(); outgoing.clear(); notifyAll();
    }
    /**
     * Requests the relevant stream direction to end or closes its wrapper according to the method owner.
     * The outer socket queues authenticated EOF after pending output drains; closing does not mean the
     * peer has already consumed all bytes.
     */
    @Override public synchronized void close() { closing = true; }
    private final class Output extends OutputStream {
        /**
         * Writes the supplied value to the output used by the bounded encrypted byte-stream socket.
         *
         * @param value the value supplied to this operation
         * @throws IOException if input/output, stored-state validation or resource handling fails
         */
        @Override public void write(int value) throws IOException { write(new byte[]{(byte) value}); }
        /**
         * Writes the supplied value to the output used by the bounded encrypted byte-stream socket.
         *
         * @param bytes the bytes supplied to this operation
         * @param offset the offset supplied to this operation
         * @param length the requested or declared byte count
         * @throws IOException if input/output, stored-state validation or resource handling fails
         */
        @Override public void write(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            synchronized (KryptSocket.this) {
                if (failure != null) throw failure;
                if (closing) throw new IOException("Stream output closed");
                if (length > MAX_BUFFERED_BYTES - outgoing.size) throw new IOException("Stream backpressure");
                if (length != 0) outgoing.write(bytes, offset, length);
            }
        }
        /**
         * Requests the relevant stream direction to end or closes its wrapper according to the method owner.
         * The outer socket queues authenticated EOF after pending output drains; closing does not mean the
         * peer has already consumed all bytes.
         */
        @Override public void close() { KryptSocket.this.close(); }
    }
    private final class Input extends InputStream {
        /**
         * Reads the next value from the input used by the bounded encrypted byte-stream socket.
         *
         * @return the result described above
         * @throws IOException if input/output, stored-state validation or resource handling fails
         */
        @Override public int read() throws IOException {
            byte[] one = new byte[1]; return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
        }
        /**
         * Reads the next value from the input used by the bounded encrypted byte-stream socket.
         *
         * @param bytes the bytes supplied to this operation
         * @param offset the offset supplied to this operation
         * @param length the requested or declared byte count
         * @return the result described above
         * @throws IOException if input/output, stored-state validation or resource handling fails
         */
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
        /**
         * Requests the relevant stream direction to end or closes its wrapper according to the method owner.
         * The outer socket queues authenticated EOF after pending output drains; closing does not mean the
         * peer has already consumed all bytes.
         */
        @Override public void close() { fail("Stream input closed"); }
    }
    /** Byte-bounded ring queues coalesce tiny writes without retaining a million array objects. */
    private static final class ByteQueue {
        private byte[] bytes = new byte[0];
        private int head, size;
        /**
         * Reports whether empty holds for the bounded encrypted byte-stream socket.
         *
         * @return whether the condition or operation described above succeeds
         */
        boolean isEmpty() { return size == 0; }
        /**
         * Writes the supplied value to the output used by the bounded encrypted byte-stream socket.
         *
         * @param source the source supplied to this operation
         * @param offset the offset supplied to this operation
         * @param length the requested or declared byte count
         */
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
        /**
         * Reads the next value from the input used by the bounded encrypted byte-stream socket.
         *
         * @param target the target supplied to this operation
         * @param offset the offset supplied to this operation
         * @param length the requested or declared byte count
         */
        void read(byte[] target, int offset, int length) {
            int first = Math.min(length, bytes.length - head);
            System.arraycopy(bytes, head, target, offset, first);
            System.arraycopy(bytes, 0, target, offset + first, length - first);
            Arrays.fill(bytes, head, head + first, (byte) 0);
            Arrays.fill(bytes, 0, length - first, (byte) 0);
            head = (head + length) % bytes.length; size -= length;
            if (size == 0) head = 0;
        }
        /**
         * Clears retained state in the bounded encrypted byte-stream socket.
         */
        void clear() { Arrays.fill(bytes, (byte) 0); bytes = new byte[0]; head = size = 0; }
    }

}
