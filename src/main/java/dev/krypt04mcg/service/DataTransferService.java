package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.channel.ChannelCrypto;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.protocol.ControlPayload.Kind;
import dev.krypt04mcg.util.Hex;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

/** Client-thread allocation and lifecycle; Minecraft supplies ordered, reliable record delivery. */
public final class DataTransferService implements AutoCloseable {
    private static final long TIMEOUT_MS = 60000;
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final SessionService sessions;
    private final SessionHandshakeService handshakes;
    private final BooleanSupplier available;
    private final Consumer<CustomPacketPayload> transport;
    private final Thread clientThread = Thread.currentThread();
    private final Map<String, Connection> connections = new HashMap<>();
    private final Map<UUID, Stream> streams = new LinkedHashMap<>();
    private final Stream[] slots;
    private final PacketCodec packets = new PacketCodec();
    private final SharingWorker worker = new SharingWorker();
    private final Queue<Runnable> completed = new ConcurrentLinkedQueue<>();
    private final Deque<ControlPayload> exchanges = new ArrayDeque<>();
    private final Map<String, Long> seenExchanges = new HashMap<>();
    private long generation, turn;
    private boolean closed;

    /** Pass a dedicated SessionService/handshake store: API exchange must not rotate chat sessions. */
    public DataTransferService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                               SessionService sessions, SessionHandshakeService handshakes,
                               BooleanSupplier available, Consumer<CustomPacketPayload> transport) {
        this.config = config; this.keys = keys; this.trust = trust; this.sessions = sessions;
        this.handshakes = handshakes; this.available = available; this.transport = transport;
        slots = new Stream[RawChannelPayload.channelCount(config.apiChannelCount)];
    }
    private void checkThread() {
        if (Thread.currentThread() != clientThread) throw new IllegalStateException("Open streams on the Minecraft client thread");
    }
    private boolean enabled(String channel) {
        return "krypt04mcg_file:stream".equals(channel) ? config.enableFileSending || config.enableFileReceiving : config.enableDataApi;
    }
    private boolean active() { return !closed && available.getAsBoolean(); }
    private String own() { return keys.local().kemPublicKey().owner(); }
    private PublicIdentity trusted(String peer) throws Exception {
        if (peer == null || !peer.matches("[A-Za-z0-9_]{1,16}")) throw new IllegalArgumentException("Select a receiver player");
        PublicIdentity identity = keys.findPublicIdentity(peer).orElseThrow(() -> new IllegalStateException("Missing public key"));
        if (trust.trustState(peer, identity) == TrustState.DISTRUSTED) throw new IllegalStateException("Distrusted key");
        return identity;
    }
    private SessionRecord session(String peer, String expected) throws Exception {
        PublicIdentity identity = trusted(peer);
        SessionRecord s = sessions.find(peer).orElseThrow(() -> new IllegalStateException("No API session"));
        var local = keys.local();
        if (!s.peerFingerprint().equals(KeyTrustService.fingerprintPair(identity))
                || !s.localFingerprint().equals(local.kemPublicKey().fingerprint() + ":" + local.signaturePublicKey().fingerprint())
                || expected != null && !expected.equals(s.sessionId())
                || sessions.isExpired(s, config.sessionTtlMinutes, Integer.MAX_VALUE, Long.MAX_VALUE))
            throw new IllegalStateException("API session changed or expired");
        return s;
    }
    public KryptSession connect(String peer) {
        checkThread(); Objects.requireNonNull(peer);
        if (peer.equalsIgnoreCase(own())) throw new IllegalArgumentException("Cannot open a stream to yourself");
        if (!active() || !(config.enableDataApi || config.enableFileSending || config.enableFileReceiving))
            throw new IllegalStateException("API channel unavailable or disabled");
        String name = peer.toLowerCase(Locale.ROOT);
        Connection existing = connections.get(name);
        if (existing != null && !existing.disposed) {
            if (!existing.ready.isDone()) return existing.handle;
            try {
                var current = session(peer, existing.id);
                if (!sessions.isExpired(current, config.sessionTtlMinutes, config.maxMessagesPerSession, config.rotateAfterBytes)) return existing.handle;
                if (streams.values().stream().anyMatch(stream -> stream.socket.peer().equalsIgnoreCase(peer)))
                    return existing.handle;
            }
            catch (Exception e) { closeConnection(existing); }
            closeConnection(existing);
        }
        if (connections.size() >= 64) throw new IllegalStateException("API connection capacity reached");
        var connection = new Connection(peer); connections.put(name, connection);
        try {
            trusted(peer);
            try {
                var s = session(peer, null);
                if (sessions.isExpired(s, config.sessionTtlMinutes, config.maxMessagesPerSession, config.rotateAfterBytes))
                    throw new IllegalStateException("API session rotation required");
                activate(connection, s);
            } catch (Exception absent) { connection.beginQueued = true; }
        } catch (Exception e) { closeConnection(connection); }
        return connection.handle;
    }
    private void begin(Connection c) throws Exception {
        if (worker.busy()) throw new IllegalStateException("Exchange worker busy; retry connection later");
        var identity = trusted(c.peer); var local = keys.local(); var kem = config.ephemeralKemAlgorithm;
        long epoch = generation;
        worker.submit(() -> handshakes.begin(identity, local, kem, false, AeadAlgorithm.CHACHA20_POLY1305), completed::add, (packet, error) -> {
            if (packet != null) c.requestId = Hex.encode(packet.messageId());
            if (epoch != generation || c.disposed) {
                if (c.requestId != null) handshakes.cancel(c.peer, c.requestId); return;
            }
            if (error != null) { closeConnection(c); return; }
            try {
                if (local != keys.local() || !KeyTrustService.fingerprintPair(identity).equals(KeyTrustService.fingerprintPair(trusted(c.peer))))
                    throw new IllegalStateException("Identity changed");
                exchange(c.peer, packet);
            } catch (Exception e) { closeConnection(c); }
        });
    }
    private void exchange(String peer, EncryptedPacket packet) {
        transport.accept(new ControlPayload(Kind.EXCHANGE, peer, UUID.randomUUID(), -1, "", "", 0, packets.encode(packet)));
    }
    private void activate(Connection c, SessionRecord s) { c.id = s.sessionId(); c.ready.complete(c.id); }
    private void closeConnection(Connection c) {
        if (c.disposed) return;
        c.disposed = true; connections.remove(c.peer.toLowerCase(Locale.ROOT), c);
        if (c.requestId != null) handshakes.cancel(c.peer, c.requestId);
        c.ready.completeExceptionally(new IllegalStateException("API connection closed"));
        for (Stream s : List.copyOf(streams.values())) if (s.connection == c) fail(s, "Session closed", true);
    }
    public KryptSocket open(String peer, String channel) {
        checkThread(); Krypt04McgApi.validateChannel(channel);
        if (!enabled(channel) || !active()) throw new IllegalStateException("Stream transport disabled or disconnected");
        if (streams.size() >= slots.length) throw new IllegalStateException("Channel pool exhausted");
        connect(peer);
        Connection c = connections.get(peer.toLowerCase(Locale.ROOT));
        if (c == null || c.disposed) throw new IllegalStateException("Session exchange unavailable");
        var socket = new KryptSocket(peer, channel, UUID.randomUUID());
        streams.put(socket.streamId(), new Stream(socket, c));
        return socket;
    }
    public void send(String peer, String channel, byte[] bytes) {
        checkThread(); Objects.requireNonNull(bytes);
        if (bytes.length > KryptSocket.MAX_BUFFERED_BYTES) throw new IllegalArgumentException("Use a socket for larger streams");
        KryptSocket socket = open(peer == null ? config.apiReceiver : peer, channel);
        try { socket.getOutputStream().write(bytes); socket.close(); }
        catch (java.io.IOException e) { socket.fail(e.getMessage()); throw new IllegalStateException(e); }
    }
    public void receive(ControlPayload p) {
        checkThread(); if (!active()) return;
        if (p.kind() == Kind.EXCHANGE) {
            if ((config.enableDataApi || config.enableFileSending || config.enableFileReceiving) && exchanges.size() < 4) exchanges.addLast(p);
            return;
        }
        Stream s = streams.get(p.id());
        try {
            if (p.kind() == Kind.OPEN) { incoming(p); return; }
            if (s == null || !s.socket.peer().equalsIgnoreCase(p.peer())) return;
            if (p.kind() == Kind.ABORT) { fail(s, "Relay released channel", false); return; }
            if (!s.socket.channel().equals(p.channel()) || !Objects.equals(s.sessionId, p.sessionId())) return;
            if (p.kind() == Kind.ASSIGNED) {
                if (!s.openSent || s.slot >= 0 || p.slot() < 0 || p.slot() >= slots.length || slots[p.slot()] != null) return;
                bind(s, p.slot()); return;
            }
            if (s.slot != p.slot() || !ChannelCrypto.verify(session(p.peer(), s.sessionId), p, p.peer(), own())) return;
            switch (p.kind()) {
                case READY -> { if (s.openSent && !s.ready) s.ready = true; }
                case END -> {
                    if (!s.ready || s.remoteEnd || p.sequence() != s.crypto.received()) throw new IllegalStateException("Truncated stream");
                    s.remoteEnd = true; s.socket.remoteEnd(); retire(s);
                }
                case RESET -> fail(s, "Peer reset stream", false);
                default -> { }
            }
        } catch (Exception e) { if (s != null) fail(s, "Invalid stream control", true); }
    }
    private void incoming(ControlPayload p) throws Exception {
        if (!enabled(p.channel()) || streams.containsKey(p.id()) || p.slot() < 0 || p.slot() >= slots.length || slots[p.slot()] != null
                || streams.size() >= slots.length) return;
        var session = session(p.peer(), p.sessionId());
        if (!ChannelCrypto.verify(session, p, p.peer(), own())) return;
        sessions.recordApiReceived(p.peer(), session.sessionId(), p.sequence(), true, 0);
        var listener = Krypt04McgApi.socketReceiver(p.channel());
        boolean callbacks = listener == null && Krypt04McgApi.hasReceiver(p.channel());
        if (listener == null && !callbacks) {
            var reject = new ControlPayload(Kind.RESET, p.peer(), p.id(), p.slot(), p.channel(), p.sessionId(), 0, new byte[0]);
            transport.accept(signed(reject, session)); return;
        }
        var socket = new KryptSocket(p.peer(), p.channel(), p.id());
        var s = new Stream(socket, null); s.sessionId = session.sessionId(); s.callbacks = callbacks;
        streams.put(p.id(), s); bind(s, p.slot()); s.ready = true;
        try {
            control(s, Kind.READY, 0);
            if (callbacks) socket.close(); else listener.accept(socket);
        } catch (Exception e) { fail(s, "Stream listener failed", true); }
    }
    private void bind(Stream s, int slot) throws Exception {
        s.crypto = new ChannelCrypto(session(s.socket.peer(), s.sessionId), s.socket.streamId(), slot, s.socket.channel(), own(), s.socket.peer());
        s.slot = slot; slots[slot] = s;
    }
    public void receive(RawChannelPayload p) {
        checkThread(); if (!active() || p.slot() >= slots.length) return;
        Stream s = slots[p.slot()]; if (s == null) return;
        try {
            if (!s.ready || s.remoteEnd || s.socket.isFailed() || !enabled(s.socket.channel())) throw new IllegalStateException("Channel not ready");
            session(s.socket.peer(), s.sessionId);
            byte[] bytes = s.crypto.decrypt(p.ciphertext()); s.bytes += bytes.length;
            // Authenticated empty records advance the counter, but make no stream progress.
            if (bytes.length > 0) s.lastActivity = System.currentTimeMillis();
            if (s.callbacks) {
                if (!Krypt04McgApi.dispatch(s.socket.channel(), s.socket.peer(), bytes)) throw new IllegalStateException("Listener removed");
            } else s.socket.accept(bytes);
        } catch (Exception e) { fail(s, "Encrypted stream failed", true); }
    }
    public void tick() {
        checkThread(); Runnable completion;
        while ((completion = completed.poll()) != null) completion.run();
        if (!active()) { clear(); return; }
        processExchange();
        if (!worker.busy()) for (Connection c : List.copyOf(connections.values())) {
            if (!c.beginQueued || c.disposed) continue;
            c.beginQueued = false;
            try { begin(c); } catch (Exception e) { closeConnection(c); }
            break;
        }
        long now = System.currentTimeMillis();
        seenExchanges.values().removeIf(expiry -> expiry < now);
        for (Connection c : List.copyOf(connections.values()))
            if (!c.ready.isDone() && now - c.created > TIMEOUT_MS) closeConnection(c);
        int budget = 4;
        var activeStreams = new ArrayList<>(streams.values());
        if (!activeStreams.isEmpty()) Collections.rotate(activeStreams, -(int) (turn++ % activeStreams.size()));
        for (Stream s : activeStreams) {
            try {
                if (!enabled(s.socket.channel()) || s.socket.isFailed()
                        || now - s.lastActivity > TIMEOUT_MS) throw new IllegalStateException("Stream disabled, failed or timed out");
                if (!s.openSent && s.connection != null && s.connection.handle.isReady()) {
                    var session = session(s.socket.peer(), s.connection.id); s.sessionId = session.sessionId();
                    long sequence = sessions.reserveApiSend(s.socket.peer(), s.sessionId, true, 0);
                    s.openSent = true; control(s, Kind.OPEN, sequence);
                }
                if (!s.ready) continue;
                session(s.socket.peer(), s.sessionId);
                while (budget > 0) {
                    byte[] bytes = s.socket.poll(RawChannelPayload.MAX_PLAINTEXT); if (bytes == null) break;
                    budget--; s.bytes += bytes.length;
                    transport.accept(new RawChannelPayload(s.slot, s.crypto.encrypt(bytes))); s.lastActivity = now;
                }
                if (s.socket.needsEnd()) {
                    control(s, Kind.END, s.crypto.sent()); s.localEnd = true; s.socket.endSent(); retire(s);
                }
            } catch (Exception e) { fail(s, "Stream unavailable", true); }
        }
    }
    private void processExchange() {
        if (worker.busy() || exchanges.isEmpty()) return;
        var p = exchanges.removeFirst(); long epoch = generation;
        try {
            var identity = trusted(p.peer()); var local = keys.local();
            var packet = packets.decode(p.body()); long now = System.currentTimeMillis();
            String id = p.peer().toLowerCase(Locale.ROOT) + ":" + Hex.encode(packet.messageId());
            if (packet.type() != PacketType.SESSION_EXCHANGE || !p.peer().equalsIgnoreCase(packet.sender())
                    || packet.timestampMillis() < now - 300000 || packet.timestampMillis() > now + 60000
                    || seenExchanges.containsKey(id) || seenExchanges.size() >= 1024) return;
            worker.submit(() -> handshakes.decrypt(packet, local, identity), completed::add, (decrypted, error) -> {
                if (epoch != generation || error != null || !active()) return;
                try {
                    if (local != keys.local() || !KeyTrustService.fingerprintPair(identity).equals(KeyTrustService.fingerprintPair(trusted(p.peer())))) return;
                    if (handshakes.complete(packet, decrypted, identity, local, false, AeadAlgorithm.CHACHA20_POLY1305, this::exchangePacket)) {
                        seenExchanges.put(id, packet.timestampMillis() + 300000);
                        var c = connections.get(p.peer().toLowerCase(Locale.ROOT));
                        if (c != null && !c.disposed) activate(c, session(p.peer(), null));
                    }
                } catch (Exception ignored) { }
            });
        } catch (Exception ignored) { }
    }
    private void exchangePacket(EncryptedPacket packet, String peer) { exchange(peer, packet); }
    private ControlPayload signed(ControlPayload p, SessionRecord session) {
        return new ControlPayload(p.kind(), p.peer(), p.id(), p.slot(), p.channel(), p.sessionId(), p.sequence(),
                ChannelCrypto.authenticate(session, p, own(), p.peer()));
    }
    private void control(Stream s, Kind kind, long sequence) throws Exception {
        var p = new ControlPayload(kind, s.socket.peer(), s.socket.streamId(), s.slot, s.socket.channel(), s.sessionId, sequence, new byte[0]);
        transport.accept(signed(p, session(p.peer(), s.sessionId)));
    }
    private void retire(Stream s) throws Exception {
        if (s.localEnd && s.remoteEnd) {
            sessions.reserveApiSend(s.socket.peer(), s.sessionId, false, s.bytes);
            remove(s);
        }
    }
    private void fail(Stream s, String reason, boolean notify) {
        if (!streams.containsKey(s.socket.streamId())) return;
        s.socket.fail(reason);
        if (notify && s.slot >= 0 && active()) try { control(s, Kind.RESET, 0); } catch (Exception ignored) { }
        remove(s);
    }
    private void remove(Stream s) {
        streams.remove(s.socket.streamId());
        if (s.slot >= 0 && slots[s.slot] == s) slots[s.slot] = null;
        if (s.crypto != null) s.crypto.close();
    }
    public void clear() {
        generation++; exchanges.clear(); seenExchanges.clear();
        for (Connection c : List.copyOf(connections.values())) closeConnection(c);
        for (Stream s : List.copyOf(streams.values())) fail(s, "Disconnected", false);
    }
    @Override public void close() { closed = true; clear(); worker.close(); }
    private final class Connection {
        final String peer; final long created = System.currentTimeMillis();
        final CompletableFuture<String> ready = new CompletableFuture<>(); final KryptSession handle;
        String id, requestId; boolean disposed, beginQueued;
        Connection(String peer) {
            this.peer = peer;
            handle = new KryptSession(peer, ready, (channel, bytes) -> {
                if (disposed) throw new IllegalStateException("Session closed");
                send(peer, channel, bytes);
            }, () -> { checkThread(); closeConnection(this); }, () -> !disposed);
        }
    }
    private static final class Stream {
        final KryptSocket socket; final Connection connection;
        String sessionId; int slot = -1; ChannelCrypto crypto;
        boolean openSent, ready, callbacks, localEnd, remoteEnd;
        long bytes, lastActivity = System.currentTimeMillis();
        Stream(KryptSocket socket, Connection connection) { this.socket = socket; this.connection = connection; }
    }
}
