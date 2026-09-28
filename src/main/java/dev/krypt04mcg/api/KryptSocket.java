package dev.krypt04mcg.api;

import dev.krypt04mcg.config.Krypt04McgConfig;
import java.io.*;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;

/** Ordered full-duplex stream. Blocking I/O belongs on application workers. */
public final class KryptSocket implements AutoCloseable {
    // One frame fits a single CustomPayload, including AEAD and base64 plaintext overhead.
    static final int CHUNK_BYTES = 8 * 1024;
    private final String peer, channel;
    private final UUID streamId;
    private final Transport transport;
    private final Krypt04McgConfig config;
    private final Object lock = new Object();
    private final Deque<byte[]> incoming = new ArrayDeque<>();
    private final ArrayBlockingQueue<KryptStreamRegistry.Frame> outgoing;
    private final Input input = new Input();
    private final Output output = new Output();
    private final Thread writer;
    private long sendSequence, receiveSequence, submitted, completed;
    private int incomingBytes, incomingOffset;
    private boolean closing, closed, remoteClosed, inputClosed, failed;

    interface Transport { void send(KryptStreamRegistry.Frame frame) throws IOException; }

    KryptSocket(String peer, String channel, UUID streamId, Transport transport) {
        this(peer, channel, streamId, transport, new Krypt04McgConfig());
    }
    KryptSocket(String peer, String channel, UUID streamId, Transport transport, Krypt04McgConfig config) {
        this.peer = Objects.requireNonNull(peer);
        this.channel = Objects.requireNonNull(channel);
        this.streamId = Objects.requireNonNull(streamId);
        this.transport = Objects.requireNonNull(transport);
        this.config = Objects.requireNonNull(config);
        outgoing = new ArrayBlockingQueue<>(Math.max(1, config.socketMaxBufferedMiB() * 1024 * 1024 / CHUNK_BYTES));
        writer = Thread.ofVirtual().name("krypt-tunnel-output-" + streamId).start(this::pump);
    }

    public String peer() { return peer; }
    public String channel() { return channel; }
    public UUID streamId() { return streamId; }
    public InputStream getInputStream() { return input; }
    public OutputStream getOutputStream() { return output; }
    public boolean isClosed() { synchronized (lock) { return closed || failed; } }

    State state() { synchronized (lock) { return new State(outgoing.size(), 0, 0, 0, incomingBytes); } }
    record State(int queuedChunks, int inFlightChunks, int completedOutOfOrderChunks,
                 int reorderedIncomingChunks, int bufferedIncomingBytes) {}

    void opened() {
        synchronized (lock) { outgoing.add(KryptStreamRegistry.Frame.open(streamId, channel)); submitted++; }
    }

    void data(long sequence, byte[] bytes) {
        synchronized (lock) {
            if (failed || closed) return;
            if (remoteClosed || sequence != receiveSequence || sequence == Long.MAX_VALUE
                    || bytes == null || bytes.length == 0 || bytes.length > CHUNK_BYTES) {
                protocolError();
                return;
            }
            if (!inputClosed) {
                while (!inputClosed && !failed && !closed
                        && incomingBytes + bytes.length > config.socketMaxBufferedMiB() * 1024 * 1024) {
                    try { waitForIo(); }
                    catch (IOException e) { remoteReset(); return; }
                }
                if (failed || closed) return;
                if (inputClosed) { receiveSequence++; return; }
                incoming.addLast(bytes);
                incomingBytes += bytes.length;
            }
            receiveSequence++;
            lock.notifyAll();
        }
    }

    void protocolError() {
        synchronized (lock) {
            if (failed) return;
            failed = true;
            incoming.clear(); incomingBytes = 0; incomingOffset = 0;
            outgoing.clear();
            outgoing.offer(KryptStreamRegistry.Frame.reset(streamId));
            lock.notifyAll();
        }
    }

    void remoteClose() {
        synchronized (lock) {
            remoteClosed = true; closing = true; closed = true;
            outgoing.clear(); lock.notifyAll();
        }
    }
    void remoteReset() {
        synchronized (lock) {
            failed = true;
            incoming.clear(); incomingBytes = 0; incomingOffset = 0;
            outgoing.clear(); lock.notifyAll();
        }
        writer.interrupt();
    }

    private void pump() {
        try {
            while (true) {
                KryptStreamRegistry.Frame frame = outgoing.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS);
                synchronized (lock) {
                    lock.notifyAll();
                    if (remoteClosed) return;
                    if (frame == null && closing) frame = KryptStreamRegistry.Frame.close(streamId);
                }
                if (frame == null) continue;
                transport.send(frame);
                synchronized (lock) { completed++; lock.notifyAll(); }
                if (frame.kind == KryptStreamRegistry.Kind.CLOSE || frame.kind == KryptStreamRegistry.Kind.RESET) {
                    synchronized (lock) { closed = true; lock.notifyAll(); }
                    return;
                }
            }
        } catch (IOException | RuntimeException | InterruptedException e) {
            synchronized (lock) { if (remoteClosed) return; }
            remoteReset();
        }
    }

    /** Queues CLOSE after preceding writes. No remote acknowledgement is needed. */
    @Override public void close() {
        synchronized (lock) {
            if (closing || failed) return;
            closing = true;
            lock.notifyAll();
        }
    }

    private void enqueue(KryptStreamRegistry.Frame frame) throws IOException {
        synchronized (lock) {
            while (true) {
                if (failed || closed || closing) throw new IOException("KryptSocket output is closed");
                if (outgoing.offer(frame)) { submitted++; return; }
                waitForIo();
            }
        }
    }

    private final class Output extends OutputStream {
        @Override public void write(int value) throws IOException { write(new byte[] {(byte) value}); }
        @Override public void write(byte[] source, int offset, int length) throws IOException {
            Krypt04McgApi.requireIoWorker();
            synchronized (this) { writeChunks(source, offset, length); }
        }
        private void writeChunks(byte[] source, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, source.length);
            synchronized (lock) {
                if (closing || failed || closed) throw new IOException("KryptSocket output is closed");
            }
            while (length > 0) {
                int count = Math.min(CHUNK_BYTES, length);
                enqueue(KryptStreamRegistry.Frame.data(streamId, sendSequence, Arrays.copyOfRange(source, offset, offset + count)));
                sendSequence++;
                offset += count; length -= count;
            }
        }
        /** Waits for prior frames to reach the local TCP transport, not for peer consumption. */
        @Override public void flush() throws IOException {
            Krypt04McgApi.requireIoWorker();
            synchronized (lock) {
                long target = submitted;
                while (completed < target) {
                    if (failed || closed) throw new IOException("KryptSocket output is closed");
                    waitForIo();
                }
            }
        }
        @Override public void close() { KryptSocket.this.close(); }
    }

    private final class Input extends InputStream {
        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
        }
        @Override public int read(byte[] target, int offset, int length) throws IOException {
            Krypt04McgApi.requireIoWorker();
            Objects.checkFromIndexSize(offset, length, target.length);
            if (length == 0) return 0;
            synchronized (lock) {
                while (incoming.isEmpty() && !inputClosed && !remoteClosed && !closed && !failed) waitForIo();
                if (inputClosed || failed) throw new IOException("KryptSocket input is closed or reset");
                if (incoming.isEmpty()) return -1;
                byte[] head = incoming.peekFirst();
                int count = Math.min(length, head.length - incomingOffset);
                System.arraycopy(head, incomingOffset, target, offset, count);
                incomingOffset += count; incomingBytes -= count;
                if (incomingOffset == head.length) { incoming.removeFirst(); incomingOffset = 0; }
                lock.notifyAll();
                return count;
            }
        }
        @Override public void close() {
            synchronized (lock) {
                inputClosed = true; incoming.clear(); incomingBytes = 0; incomingOffset = 0;
                lock.notifyAll();
            }
        }
    }
    private void waitForIo() throws IOException {
        try { lock.wait(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("Interrupted tunnel I/O", e); }
    }
}
