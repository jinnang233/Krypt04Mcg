package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.api.KryptStreamRegistry.*;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BiConsumer;

/** Independent ordered tunnel transport. No transfer handles, receipts, retries or ACK windows. */
public final class TunnelService implements AutoCloseable {
    @FunctionalInterface public interface Wire { void send(TunnelPayload payload) throws Exception; }
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final SessionService sessions;
    private final TunnelCounters counters;
    private final Wire wire;
    private final BiConsumer<KryptSession, byte[]> receiver;
    private final TunnelCodec codec = new TunnelCodec();
    private final Map<UUID, Stream> streams = new ConcurrentHashMap<>();
    private final ArrayBlockingQueue<Send> outgoing = new ArrayBlockingQueue<>(32);
    private final Thread writer;
    private volatile boolean closed;

    public TunnelService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                         SessionService sessions, TunnelCounters counters, Wire wire,
                         BiConsumer<KryptSession, byte[]> receiver) {
        this.config = config; this.keys = keys; this.trust = trust; this.sessions = sessions;
        this.counters = counters; this.wire = wire; this.receiver = receiver;
        writer = Thread.ofVirtual().name("krypt-tunnel-encrypt").start(this::pump);
    }

    /** Called on the client thread; only attaches a worker transport to the existing handshake handle. */
    public KryptSession attach(KryptSession session) {
        return session.withStreamSender(frame -> {
            try {
                session.ready().toCompletableFuture().get();
                send(session.peer(), session.sessionId(), frame);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); throw new IOException("Interrupted tunnel readiness", e);
            } catch (ExecutionException e) { throw new IOException("Tunnel session unavailable", e.getCause()); }
        });
    }

    private void send(String peer, String sessionId, byte[] bytes) throws IOException {
        Send task = new Send(peer, sessionId, bytes, new CompletableFuture<>());
        try {
            while (!outgoing.offer(task, 100, TimeUnit.MILLISECONDS))
                if (closed) throw new IOException("Tunnel disconnected");
            if (closed && outgoing.remove(task)) throw new IOException("Tunnel disconnected");
            task.done.get(); // Local transport completion, never a remote receipt.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); throw new IOException("Interrupted tunnel send", e);
        } catch (ExecutionException e) { throw new IOException("Tunnel send failed", e.getCause()); }
    }

    private void pump() {
        try {
            while (!closed) {
                Send task = outgoing.take();
                try { transmit(task); task.done.complete(null); }
                catch (Exception e) { task.done.completeExceptionally(e); }
            }
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        finally {
            IOException error = new IOException("Tunnel disconnected");
            Send abandoned;
            while ((abandoned = outgoing.poll()) != null) abandoned.done.completeExceptionally(error);
        }
    }

    private void transmit(Send task) throws Exception {
        Frame frame = Frame.decode(task.bytes);
        Stream stream = streams.get(frame.streamId);
        if (frame.kind == Kind.OPEN) {
            if (streams.size() >= config.maxDataTransfers()) throw new IOException("Too many tunnel streams");
            SessionRecord session = current(task.peer, task.sessionId);
            stream = new Stream(task.peer, session, counters.reserve(task.peer, session.sessionId()));
            if (streams.putIfAbsent(frame.streamId, stream) != null) throw new IOException("Duplicate OPEN");
        }
        if (stream == null || !stream.peer.equalsIgnoreCase(task.peer)
                || !stream.session.sessionId().equals(task.sessionId)) throw new IOException("Unknown tunnel stream");
        validateLive(stream);
        if (stream.send == Long.MAX_VALUE) throw new IOException("Tunnel counter exhausted");
        byte[] encrypted = codec.encrypt(stream.session, keys.local().kemPublicKey().owner(), stream.peer,
                frame.streamId, stream.lease, stream.send++, task.bytes, config.aeadAlgorithm);
        wire.send(new TunnelPayload(stream.peer, encrypted));
        if (frame.kind == Kind.CLOSE || frame.kind == Kind.RESET) streams.remove(frame.streamId, stream);
    }

    /** Called serially on the tunnel input worker. It may block on a socket's bounded receive queue. */
    public void receive(TunnelPayload payload) throws Exception {
        if (closed || !config.enableDataApi) throw new IOException("Tunnel unavailable");
        var header = codec.header(payload.envelope());
        Stream stream = streams.get(header.stream());
        SessionRecord session = stream == null ? current(payload.peer(), header.packet().sessionId()) : stream.session;
        if (stream != null) {
            if (!stream.peer.equalsIgnoreCase(payload.peer()) || stream.lease != header.lease())
                throw new IOException("Tunnel binding mismatch");
            validateLive(stream);
        }
        byte[] bytes = codec.decrypt(header, session, keys.local().kemPublicKey().owner(), payload.peer());
        Frame frame = Frame.decode(bytes);
        if (!frame.streamId.equals(header.stream())) throw new IOException("Tunnel streamId mismatch");
        if (stream == null) {
            if (frame.kind != Kind.OPEN || header.packet().sequence() != 0)
                throw new IOException("Missing authenticated OPEN");
            if (streams.size() >= config.maxDataTransfers()) throw new IOException("Too many tunnel streams");
            counters.accept(payload.peer(), session.sessionId(), header.lease());
            stream = new Stream(payload.peer(), session, header.lease());
            if (streams.putIfAbsent(frame.streamId, stream) != null) throw new IOException("Duplicate OPEN");
        } else if (frame.kind == Kind.OPEN) throw new IOException("Duplicate OPEN");
        if (header.packet().sequence() != stream.receive++) throw new IOException("Tunnel counter mismatch");
        Stream accepted = stream;
        var handle = new KryptSession(stream.peer, CompletableFuture.completedFuture(session.sessionId()),
                (channel, data) -> { throw new UnsupportedOperationException("Use the Data API for messages"); },
                () -> {}, () -> !closed).withStreamSender(reply -> send(accepted.peer, session.sessionId(), reply));
        receiver.accept(handle, bytes);
        if (frame.kind == Kind.CLOSE || frame.kind == Kind.RESET) streams.remove(frame.streamId, stream);
    }

    private SessionRecord current(String peer, String expected) throws Exception {
        if (!config.enableDataApi || closed) throw new IOException("Tunnel unavailable");
        var identity = keys.findPublicIdentity(peer).orElseThrow(() -> new IOException("Missing peer identity"));
        if (trust.trustState(peer, identity) == TrustState.DISTRUSTED) throw new IOException("Distrusted tunnel peer");
        var local = keys.local();
        var session = sessions.find(peer).orElseThrow(() -> new IOException("Missing tunnel session"));
        String own = local.kemPublicKey().fingerprint() + ":" + local.signaturePublicKey().fingerprint();
        if (!session.sessionId().equals(expected) || !session.localFingerprint().equals(own)
                || !session.peerFingerprint().equals(KeyTrustService.fingerprintPair(identity))
                || sessions.isExpired(session, config.sessionTtlMinutes, Integer.MAX_VALUE, Long.MAX_VALUE))
            throw new IOException("Tunnel session changed or expired");
        return session;
    }

    private void validateLive(Stream stream) throws Exception {
        if (closed || !config.enableDataApi) throw new IOException("Tunnel unavailable");
        long now = System.nanoTime();
        if (now - stream.checked > TimeUnit.SECONDS.toNanos(1)) {
            current(stream.peer, stream.session.sessionId());
            stream.checked = now;
        }
    }

    public int streamCount() { return streams.size(); }
    @Override public void close() {
        closed = true; writer.interrupt(); streams.clear();
    }
    private record Send(String peer, String sessionId, byte[] bytes, CompletableFuture<Void> done) {}
    private static final class Stream {
        final String peer;
        final SessionRecord session;
        final long lease;
        long send, receive;
        volatile long checked = System.nanoTime();
        Stream(String peer, SessionRecord session, long lease) {
            this.peer = peer; this.session = session; this.lease = lease;
        }
    }
}
