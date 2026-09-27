package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.api.TransferResult.Status;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.protocol.DataTransferCodec.Kind;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** Client-thread state machine; only immutable snapshots cross the single crypto worker. */
public final class DataTransferService implements AutoCloseable {
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final BooleanSupplier available;
    private final Consumer<DataPayload> transport;
    private final LongSupplier clock;
    private final Thread clientThread = Thread.currentThread();
    private SessionService sessions;
    private SessionHandshakeService handshakes;
    private final Map<String, Connection> connections = new HashMap<>();
    private final Map<String, Long> exchanges = new HashMap<>();
    private final DataTransferCodec codec = new DataTransferCodec();
    private final SharingWorker worker = new SharingWorker();
    private final Queue<Runnable> completions = new ConcurrentLinkedQueue<>();
    private final OptionalTransferAssembler parts = new OptionalTransferAssembler(FileTransferCodec.MAX_CHUNKS, 4);
    private final Deque<Pending> pending = new ArrayDeque<>();
    private final Deque<Incoming> incoming = new ArrayDeque<>();
    private final Deque<Receipt> receipts = new ArrayDeque<>();
    private final Deque<Wire> controls = new ArrayDeque<>();
    private final Map<String, Seen> seen = new HashMap<>();
    // Deliberately one in-flight DataTransfer: SessionService currently persists a monotonic
    // receive sequence, not a bounded reorder window. Parallel retries could make an older,
    // otherwise valid sequence arrive after a newer one and be rejected as replay.
    private Wire wire;
    private long queuedBytes, incomingChars, generation;
    private boolean preferSend, preparingReceipt, closed, resetting;

    public DataTransferService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                               BooleanSupplier available, Consumer<DataPayload> transport) {
        this(config, keys, trust, available, transport, System::currentTimeMillis);
    }

    DataTransferService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                        BooleanSupplier available, Consumer<DataPayload> transport, LongSupplier clock) {
        this.config = config; this.keys = keys; this.trust = trust;
        this.available = available; this.transport = transport; this.clock = clock;
    }

    public DataTransferService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                               SessionService sessions, SessionHandshakeService handshakes,
                               BooleanSupplier available, Consumer<DataPayload> transport) {
        this(config, keys, trust, sessions, handshakes, available, transport, System::currentTimeMillis);
    }

    DataTransferService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                        SessionService sessions, SessionHandshakeService handshakes,
                        BooleanSupplier available, Consumer<DataPayload> transport, LongSupplier clock) {
        this(config, keys, trust, available, transport, clock);
        this.sessions = Objects.requireNonNull(sessions);
        this.handshakes = Objects.requireNonNull(handshakes);
    }

    public KryptSession connect(String player) {
        requireClientThread();
        if (sessions == null) throw new IllegalStateException("Session API unavailable");
        Objects.requireNonNull(player, "player");
        String peer = player.toLowerCase(Locale.ROOT);
        Connection existing = connections.get(peer);
        if (existing != null && !existing.disposed) {
            if (!existing.ready.isDone()) return existing.handle;
            try { currentSession(player, existing.identity, existing.local, existing.id, false); return existing.handle; }
            catch (Exception ignored) { closeConnection(existing, Status.FAILED); }
        }
        Connection connection = new Connection(player);
        try {
            if (!active(generation) || resetting || connections.size() >= config.maxDataTransfers())
                throw new IllegalStateException("Session API disabled, unavailable or at capacity");
            connection.identity = trusted(player);
            connection.local = keys.local();
            connections.put(peer, connection);
            try { activate(connection, currentSession(player, connection.identity, connection.local, null, false)); }
            catch (Exception noSession) {
                enqueue(player, "", new byte[0], null, Kind.EXCHANGE, connection, true)
                        .whenComplete(result -> {
                            if (result.status() != Status.DELIVERED && !connection.ready.isDone()) closeConnection(connection, result.status());
                        });
            }
        } catch (Exception e) { closeConnection(connection, Status.FAILED); }
        return connection.handle;
    }

    private void requireClientThread() {
        if (Thread.currentThread() != clientThread) throw new IllegalStateException("Call the session API on the client thread");
    }

    private void activate(Connection connection, SessionRecord session) {
        if (!connection.disposed && !connection.ready.isDone()) {
            connection.id = session.sessionId();
            // A simultaneous inbound exchange can win before our queued request is sent.
            for (Pending request : List.copyOf(pending))
                if (request.begin == connection) finish(request, Status.DELIVERED);
            connection.ready.complete(connection.id);
        }
    }

    private void closeConnection(Connection connection, Status status) {
        if (connection.disposed) return;
        connection.disposed = true;
        connections.remove(connection.peer.toLowerCase(Locale.ROOT), connection);
        if (connection.requestId != null) handshakes.cancel(connection.peer, connection.requestId);
        connection.ready.completeExceptionally(new IllegalStateException("Session connection " + status));
        for (Pending request : List.copyOf(pending))
            if (request.connection == connection || request.begin == connection) finish(request, status);
    }

    private SessionRecord currentSession(String peer, PublicIdentity identity, LocalKeyMaterial local,
                                          String expectedId, boolean receipt) throws Exception {
        if (sessions == null || !stillTrusted(peer, identity, local)) throw new IllegalStateException("Invalid session identity");
        SessionRecord session = sessions.find(peer).orElseThrow(() -> new IllegalStateException("No session"));
        String own = local.kemPublicKey().fingerprint() + ":" + local.signaturePublicKey().fingerprint();
        if (!own.equals(session.localFingerprint()) || !session.peerFingerprint().equals(KeyTrustService.fingerprintPair(identity))
                || (expectedId != null && !expectedId.equals(session.sessionId()))
                || sessions.isApiExpired(session, config.sessionTtlMinutes,
                        receipt ? Integer.MAX_VALUE : config.apiMaxMessagesPerSession,
                        receipt ? Long.MAX_VALUE : config.apiRotateAfterBytes))
            throw new IllegalStateException("Session changed or expired");
        return session;
    }

    public DataTransfer send(String player, String channel, byte[] data) {
        return enqueue(player, channel, data, null, Kind.DATA, null, false);
    }

    private DataTransfer enqueue(String player, String channel, byte[] data, Connection connection, Kind kind,
                                  Connection begin, boolean priority) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        Pending request = new Pending(player == null ? config.apiReceiver : player, channel,
                data.length + 2L * channel.length(), clock.getAsLong());
        request.connection = connection; request.kind = kind; request.begin = begin;
        Status failure = closed || resetting ? Status.DISCONNECTED : !config.enableDataApi ? Status.DISABLED
                : !available.getAsBoolean() ? Status.DISCONNECTED : null;
        if (failure == null && (pending.size() >= config.maxDataTransfers() || data.length > FileTransferCodec.MAX_FILE_BYTES
                || request.weight > config.maxDataQueuedMiB() * 1024L * 1024L - queuedBytes)) failure = Status.BACKPRESSURE;
        if (connection != null && connection.disposed) failure = Status.FAILED;
        if (failure == null) {
            try { request.identity = trusted(request.peer); request.local = keys.local(); }
            catch (Exception e) { failure = Status.FAILED; }
        }
        if (failure != null) request.complete(failure);
        else {
            request.bytes = data.clone(); // Caller mutations cannot change an enqueued message.
            queuedBytes += request.weight;
            if (priority) pending.addFirst(request); else pending.addLast(request);
        }
        return request.handle;
    }

    public void receive(DataPayload payload) {
        if (closed || !config.enableDataApi || !available.getAsBoolean() || payload.version() != 1) return;
        try {
            var assembled = parts.accept(payload.peer(), payload.fragment(), clock.getAsLong(), () -> {
                try { trusted(payload.peer()); return incoming.size() < 4; }
                catch (Exception e) { return false; }
            });
            if (assembled.isEmpty()) return;
            String encoded = assembled.get();
            if (incoming.size() >= 4 || encoded.length() + incomingChars > 32L * 1024 * 1024) return;
            incoming.addLast(new Incoming(payload.peer(), encoded, trusted(payload.peer()), keys.local()));
            incomingChars += encoded.length();
        } catch (Exception ignored) { /* Unauthenticated input never produces a NACK. */ }
    }

    public void tick() {
        Runnable completion;
        while ((completion = completions.poll()) != null) completion.run();
        if (closed || !config.enableDataApi || !available.getAsBoolean()) {
            reset(!config.enableDataApi ? Status.DISABLED : Status.DISCONNECTED, false);
            return;
        }
        long now = clock.getAsLong();
        long epoch = generation;
        parts.expire(now);
        seen.values().removeIf(entry -> entry.expires < now);
        exchanges.values().removeIf(expiry -> expiry < now);
        for (Connection connection : List.copyOf(connections.values()))
            if (!connection.ready.isDone() && now - connection.created >= config.dataTransferTimeoutSeconds() * 1000L) closeConnection(connection, Status.TIMEOUT);
        // Complete outside iteration: an observer may immediately enqueue another transfer.
        for (Pending request : List.copyOf(pending)) {
            if (now - request.created >= config.dataTransferTimeoutSeconds() * 1000L) finish(request, Status.TIMEOUT);
            else if (request.waiting && now >= request.ackDeadline) {
                if (request.attempts >= config.maxDataAttempts()) finish(request, Status.TIMEOUT);
                else request.waiting = false;
            }
        }
        // Completion observers may disable the API or disconnect while finishing a timeout.
        if (!active(epoch)) return;
        prepare();
        // Finish each envelope before selecting a receipt; the assembler admits one per sender.
        for (int i = 0; i < config.dataFragmentsPerTick() && active(epoch); i++) {
            if (wire == null) {
                wire = controls.pollFirst();
                Pending head = pending.peekFirst();
                if (wire == null && head != null && head.ready != null) {
                    wire = head.ready; head.ready = null; head.inFlight = true; head.attempts++;
                }
            }
            if (wire == null) break;
            Wire current = wire;
            try {
                if (!stillTrusted(current.peer, current.identity, current.local)) throw new IllegalStateException("Key changed");
                if (current.session != null) currentSession(current.peer, current.identity, current.local, current.session.sessionId(), true);
                transport.accept(new DataPayload(current.peer, current.fragments.get(current.index++), 1));
                if (wire != current) continue;
                if (current.index == current.fragments.size()) {
                    wire = null;
                    if (current.request != null) {
                        current.request.inFlight = false;
                        current.request.waiting = true;
                        current.request.ackDeadline = now + config.dataAckTimeoutSeconds() * 1000L;
                    }
                }
            } catch (Exception e) {
                wire = null;
                if (current.request != null) finish(current.request, Status.FAILED);
            }
        }
    }

    private void prepare() {
        if (worker.busy()) return;
        long epoch = generation;
        Receipt receipt = receipts.pollFirst();
        if (receipt != null) {
            preparingReceipt = true;
            var algorithm = config.aeadAlgorithm;
            SessionRecord session;
            long sequence;
            try {
                session = receipt.session == null ? null : currentSession(receipt.peer, receipt.identity, receipt.local, receipt.session.sessionId(), true);
                sequence = session == null ? 0 : sessions.reserveApiSend(receipt.peer, session.sessionId(), true, 0);
            } catch (Exception e) { preparingReceipt = false; return; }
            worker.submit(() -> new Wire(receipt.peer, receipt.identity, receipt.local, null,
                    session == null ? codec.receipt(receipt.id, receipt.kind, receipt.identity, receipt.local, algorithm)
                            : codec.encryptSession(receipt.id, null, null, receipt.kind, receipt.identity, receipt.local, session, sequence, algorithm),
                    session), completions::add,
                    (prepared, error) -> {
                        if (epoch != generation) return;
                        preparingReceipt = false;
                        if (error == null && active(epoch)) controls.addLast(prepared);
                    });
            return;
        }
        Pending head = pending.peekFirst();
        boolean canPrepare = head != null && !head.preparing && !head.inFlight && !head.waiting && head.ready == null;
        if (canPrepare && head.connection != null && !head.connection.ready.isDone()) canPrepare = false;
        if (!incoming.isEmpty() && (!preferSend || !canPrepare)) {
            Incoming input = incoming.removeFirst();
            preferSend = true;
            worker.submit(() -> {
                var packet = codec.packet(input.encoded, input.peer, clock.getAsLong());
                SessionRecord session = packet.type() == PacketType.SESSION_MESSAGE
                        ? currentSession(input.peer, input.identity, input.local, packet.sessionId(), true) : null;
                return new Verified(packet, session == null ? codec.decrypt(packet, input.local, input.identity)
                        : codec.decryptSession(packet, input.local, input.identity, session), session);
            }, completions::add, (verified, error) -> {
                if (epoch != generation) return;
                incomingChars -= input.encoded.length();
                if (error == null && active(epoch) && stillTrusted(input.peer, input.identity, input.local)) {
                    try {
                        if (verified.session != null) currentSession(input.peer, input.identity, input.local, verified.session.sessionId(), true);
                        accept(input, verified);
                    } catch (Exception ignored) { /* Session rotation or replay invalidates queued input. */ }
                }
            });
        } else if (canPrepare) {
            preferSend = false;
            head.preparing = true;
            byte[] bytes = head.bytes;
            String existing = head.encoded;
            var algorithm = config.aeadAlgorithm;
            var ephemeral = config.ephemeralKemAlgorithm;
            long sequence;
            try {
                if (head.connection != null) {
                    if (head.connection.disposed || head.connection.id == null) throw new IllegalStateException("Session not ready");
                    SessionRecord current = currentSession(head.peer, head.identity, head.local, head.connection.id, existing != null);
                    if (existing == null) head.session = current;
                }
                sequence = existing == null && head.session != null
                        ? sessions.reserveApiSend(head.peer, head.session.sessionId(), false, bytes.length) : 0;
            } catch (Exception e) { head.preparing = false; finish(head, Status.FAILED); return; }
            worker.submit(() -> {
                // Retry the same signed packet, with a fresh assembly ID for a lost ACK.
                String requestId = null;
                try {
                    String encoded = existing;
                    if (encoded == null && head.begin != null) {
                        var request = handshakes.begin(head.identity, head.local, ephemeral, false, algorithm);
                        requestId = Hex.encode(request.messageId());
                        encoded = codec.exchange(head.id, codec.encodePacket(request), head.identity, head.local, algorithm);
                    } else if (encoded == null && head.kind == Kind.EXCHANGE)
                        encoded = codec.exchange(head.id, bytes, head.identity, head.local, algorithm);
                    else if (encoded == null) encoded = head.session == null
                            ? codec.encrypt(head.id, head.channel, bytes, head.identity, head.local, algorithm)
                            : codec.encryptSession(head.id, head.channel, bytes, Kind.DATA, head.identity, head.local, head.session, sequence, algorithm);
                    return new Prepared(encoded, new Wire(head.peer, head.identity, head.local, head, encoded, head.session), requestId);
                } catch (Exception e) {
                    if (requestId != null) handshakes.cancel(head.peer, requestId);
                    throw e;
                }
            }, completions::add, (prepared, error) -> {
                if (prepared != null && prepared.requestId != null) {
                    if (epoch != generation || !pending.contains(head)) handshakes.cancel(head.peer, prepared.requestId);
                    else head.begin.requestId = prepared.requestId;
                }
                if (epoch != generation || !pending.contains(head)) return;
                head.preparing = false;
                if (error != null) finish(head, Status.FAILED);
                else if (active(epoch)) {
                    head.bytes = null;
                    head.encoded = prepared.encoded;
                    head.ready = prepared.wire;
                }
            });
        }
    }

    private void accept(Incoming input, Verified verified) {
        var packet = verified.packet;
        var data = verified.data;
        if (packet.timestampMillis() < clock.getAsLong() - 300000) return;
        if (data.kind() == Kind.ACK || data.kind() == Kind.NACK) {
            if (verified.session != null) {
                try { sessions.recordApiReceived(input.peer, packet.sessionId(), packet.sequence(), true, 0); }
                catch (Exception e) { return; }
            }
            for (Pending request : List.copyOf(pending)) {
                if (request.id.equals(data.transferId()) && request.attempts > 0 && request.local == input.local
                        && request.peer.equalsIgnoreCase(packet.sender())
                        && (request.session == null ? verified.session == null
                            : verified.session != null && request.session.sessionId().equals(packet.sessionId()))
                        && KeyTrustService.fingerprintPair(request.identity).equals(KeyTrustService.fingerprintPair(input.identity)))
                    finish(request, clock.getAsLong() - request.created >= config.dataTransferTimeoutSeconds() * 1000L ? Status.TIMEOUT
                            : data.kind() == Kind.ACK ? Status.DELIVERED : Status.REJECTED);
            }
            return;
        }
        String packetId = Base64Url.encode(packet.messageId());
        String id = packet.sender().toLowerCase(Locale.ROOT) + ":" +
                (data.transferId() == null ? "legacy:" + packetId : data.transferId());
        Seen previous = seen.get(id);
        Kind result;
        if (previous != null) {
            if (!previous.packetId.equals(packetId)) return;
            result = previous.result;
        } else if (seen.size() >= 1024) result = Kind.NACK;
        else {
            // Reserve deduplication before third-party code, including callbacks that throw.
            long epoch = generation;
            Seen entry = new Seen(packetId, packet.timestampMillis() + 300000);
            seen.put(id, entry);
            try {
                if (data.kind() == Kind.EXCHANGE) {
                    acceptExchange(input, data.bytes());
                    entry.result = Kind.ACK;
                } else {
                    if (verified.session != null) {
                        currentSession(input.peer, input.identity, input.local, packet.sessionId(), false);
                        sessions.recordApiReceived(input.peer, packet.sessionId(), packet.sequence(), false, data.bytes().length);
                    }
                    entry.result = Krypt04McgApi.dispatch(data.channel(), packet.sender(), data.bytes()) ? Kind.ACK : Kind.NACK;
                }
            } catch (Exception ignored) { entry.result = Kind.NACK; }
            if (!active(epoch)) return;
            result = entry.result;
        }
        if (data.transferId() != null && receipts.size() + controls.size() + (preparingReceipt ? 1 : 0)
                + (wire != null && wire.request == null ? 1 : 0) < config.maxDataReceipts())
            receipts.addLast(new Receipt(input.peer, data.transferId(), result, input.identity, input.local, verified.session));
    }

    private void acceptExchange(Incoming input, byte[] bytes) throws Exception {
        if (handshakes == null) throw new IllegalStateException("Session API unavailable");
        var packet = codec.decodePacket(bytes);
        long now = clock.getAsLong();
        String id = input.peer.toLowerCase(Locale.ROOT) + ":" + Hex.encode(packet.messageId());
        if (packet.type() != PacketType.SESSION_EXCHANGE || !input.peer.equalsIgnoreCase(packet.sender())
                || packet.timestampMillis() < now - 300000 || packet.timestampMillis() > now + 60000
                || exchanges.containsKey(id) || exchanges.size() >= 1024) throw new IllegalArgumentException("Invalid exchange");
        var decrypted = handshakes.decrypt(packet, input.local, input.identity);
        boolean established = handshakes.complete(packet, decrypted, input.identity, input.local, false, config.aeadAlgorithm,
                (response, peer) -> {
                    var sent = enqueue(peer, "", codec.encodePacket(response), null, Kind.EXCHANGE, null, true);
                    var immediate = sent.completion().toCompletableFuture();
                    if (immediate.isDone() && immediate.join().status() != Status.DELIVERED)
                        throw new IllegalStateException("No room for exchange response");
                });
        exchanges.put(id, packet.timestampMillis() + 300000);
        if (established) {
            Connection connection = connections.get(input.peer.toLowerCase(Locale.ROOT));
            if (connection != null) activate(connection, currentSession(input.peer, input.identity, input.local, null, false));
        }
    }

    private boolean active(long epoch) {
        return epoch == generation && !closed && config.enableDataApi && available.getAsBoolean();
    }

    private boolean stillTrusted(String peer, PublicIdentity identity, LocalKeyMaterial local) {
        try {
            return local == keys.local() && KeyTrustService.fingerprintPair(identity).equals(KeyTrustService.fingerprintPair(trusted(peer)));
        } catch (Exception e) { return false; }
    }

    private void finish(Pending request, Status status) {
        if (!pending.remove(request)) return;
        queuedBytes -= request.weight;
        if (wire != null && wire.request == request) wire = null;
        request.bytes = null; request.encoded = null; request.ready = null;
        request.complete(status);
    }

    private void reset(Status status, boolean forgetSeen) {
        resetting = true;
        generation++;
        for (Connection connection : List.copyOf(connections.values())) closeConnection(connection, status);
        var abandoned = List.copyOf(pending);
        pending.clear(); incoming.clear(); receipts.clear(); controls.clear(); parts.clear();
        wire = null; queuedBytes = 0; incomingChars = 0; preparingReceipt = false;
        if (forgetSeen) seen.clear();
        for (Pending request : abandoned) {
            request.bytes = null; request.encoded = null; request.ready = null;
            request.complete(status);
        }
        resetting = false;
    }

    public void clear() { reset(Status.DISCONNECTED, true); }
    @Override public void close() { closed = true; clear(); worker.close(); }

    private PublicIdentity trusted(String player) throws Exception {
        if (player == null || !player.matches("[A-Za-z0-9_]{1,16}")) throw new IllegalArgumentException("Select an API receiver player");
        var identity = keys.findPublicIdentity(player).orElseThrow(() -> new IllegalStateException("Missing public key"));
        if (trust.trustState(player, identity) == TrustState.DISTRUSTED) throw new IllegalStateException("Distrusted public key");
        return identity;
    }

    private static final class Pending {
        final UUID id = UUID.randomUUID();
        final CompletableFuture<TransferResult> completion = new CompletableFuture<>();
        final DataTransfer handle = new DataTransfer(id, completion);
        final String peer, channel;
        final long weight, created;
        byte[] bytes;
        String encoded;
        PublicIdentity identity;
        LocalKeyMaterial local;
        Connection connection, begin;
        Kind kind;
        SessionRecord session;
        Wire ready;
        boolean preparing, inFlight, waiting;
        int attempts;
        long ackDeadline;
        Pending(String peer, String channel, long weight, long created) {
            this.peer = peer; this.channel = channel; this.weight = weight; this.created = created;
        }
        void complete(Status status) { completion.complete(new TransferResult(id, status)); }
    }

    private static final class Wire {
        final String peer;
        final PublicIdentity identity;
        final LocalKeyMaterial local;
        final Pending request;
        final SessionRecord session;
        final List<String> fragments;
        int index;
        Wire(String peer, PublicIdentity identity, LocalKeyMaterial local, Pending request, String encoded, SessionRecord session) {
            this.peer = peer; this.identity = identity; this.local = local; this.request = request;
            this.session = session;
            fragments = OptionalTransferAssembler.split(encoded, FileTransferCodec.MAX_CHUNKS);
        }
    }
    private static final class Seen {
        final String packetId;
        final long expires;
        Kind result = Kind.NACK;
        Seen(String packetId, long expires) { this.packetId = packetId; this.expires = expires; }
    }
    private record Incoming(String peer, String encoded, PublicIdentity identity, LocalKeyMaterial local) {}
    private record Receipt(String peer, UUID id, Kind kind, PublicIdentity identity, LocalKeyMaterial local, SessionRecord session) {}
    private record Verified(EncryptedPacket packet, DataTransferCodec.Data data, SessionRecord session) {}
    private record Prepared(String encoded, Wire wire, String requestId) {}

    private final class Connection {
        final String peer;
        final long created = clock.getAsLong();
        final CompletableFuture<String> ready = new CompletableFuture<>();
        final KryptSession handle;
        PublicIdentity identity;
        LocalKeyMaterial local;
        String id, requestId;
        boolean disposed;
        Connection(String peer) {
            this.peer = peer;
            handle = new KryptSession(peer, ready, (channel, data) -> {
                requireClientThread();
                return enqueue(peer, channel, data, this, Kind.DATA, null, false);
            }, () -> { requireClientThread(); closeConnection(this, Status.FAILED); }, () -> !disposed);
        }
    }
}
