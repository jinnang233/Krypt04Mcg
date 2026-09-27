package dev.krypt04mcg.service;

import dev.krypt04mcg.api.*;
import dev.krypt04mcg.api.TransferResult.Status;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.protocol.DataTransferCodec.Kind;
import dev.krypt04mcg.util.Base64Url;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** Client-thread state machine; only immutable snapshots cross the single crypto worker. */
public final class DataTransferService implements AutoCloseable {
    static final int MAX_TRANSFERS = 16, MAX_RECEIPTS = 32, MAX_ATTEMPTS = 3;
    static final long MAX_QUEUED_BYTES = 16L * 1024 * 1024;
    // Longer than the assembler's 60-second lifetime, allowing incomplete attempts to expire.
    static final long ACK_TIMEOUT_MS = 65000, TRANSFER_TIMEOUT_MS = 240000;
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final BooleanSupplier available;
    private final Consumer<DataPayload> transport;
    private final LongSupplier clock;
    private final DataTransferCodec codec = new DataTransferCodec();
    private final SharingWorker worker = new SharingWorker();
    private final Queue<Runnable> completions = new ConcurrentLinkedQueue<>();
    private final OptionalTransferAssembler parts = new OptionalTransferAssembler(FileTransferCodec.MAX_CHUNKS, 4);
    private final Deque<Pending> pending = new ArrayDeque<>();
    private final Deque<Incoming> incoming = new ArrayDeque<>();
    private final Deque<Receipt> receipts = new ArrayDeque<>();
    private final Deque<Wire> controls = new ArrayDeque<>();
    private final Map<String, Seen> seen = new HashMap<>();
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

    public DataTransfer send(String player, String channel, byte[] data) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        Pending request = new Pending(player == null ? config.apiReceiver : player, channel,
                data.length + 2L * channel.length(), clock.getAsLong());
        Status failure = closed || resetting ? Status.DISCONNECTED : !config.enableDataApi ? Status.DISABLED
                : !available.getAsBoolean() ? Status.DISCONNECTED : null;
        if (failure == null && (pending.size() >= MAX_TRANSFERS || data.length > FileTransferCodec.MAX_FILE_BYTES
                || request.weight > MAX_QUEUED_BYTES - queuedBytes)) failure = Status.BACKPRESSURE;
        if (failure == null) {
            try { request.identity = trusted(request.peer); request.local = keys.local(); }
            catch (Exception e) { failure = Status.FAILED; }
        }
        if (failure != null) request.complete(failure);
        else {
            request.bytes = data.clone(); // Caller mutations cannot change an enqueued message.
            queuedBytes += request.weight;
            pending.addLast(request);
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
        // Complete outside iteration: an observer may immediately enqueue another transfer.
        for (Pending request : List.copyOf(pending)) {
            if (now - request.created >= TRANSFER_TIMEOUT_MS) finish(request, Status.TIMEOUT);
            else if (request.waiting && now >= request.ackDeadline) {
                if (request.attempts >= MAX_ATTEMPTS) finish(request, Status.TIMEOUT);
                else request.waiting = false;
            }
        }
        // Completion observers may disable the API or disconnect while finishing a timeout.
        if (!active(epoch)) return;
        prepare();
        // Finish each envelope before selecting a receipt; the assembler admits one per sender.
        for (int i = 0; i < 4 && active(epoch); i++) {
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
                transport.accept(new DataPayload(current.peer, current.fragments.get(current.index++), 1));
                if (wire != current) continue;
                if (current.index == current.fragments.size()) {
                    wire = null;
                    if (current.request != null) {
                        current.request.inFlight = false;
                        current.request.waiting = true;
                        current.request.ackDeadline = now + ACK_TIMEOUT_MS;
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
            worker.submit(() -> new Wire(receipt.peer, receipt.identity, receipt.local, null,
                    codec.receipt(receipt.id, receipt.kind, receipt.identity, receipt.local, algorithm)), completions::add,
                    (prepared, error) -> {
                        if (epoch != generation) return;
                        preparingReceipt = false;
                        if (error == null && active(epoch)) controls.addLast(prepared);
                    });
            return;
        }
        Pending head = pending.peekFirst();
        boolean canPrepare = head != null && !head.preparing && !head.inFlight && !head.waiting && head.ready == null;
        if (!incoming.isEmpty() && (!preferSend || !canPrepare)) {
            Incoming input = incoming.removeFirst();
            preferSend = true;
            worker.submit(() -> {
                var packet = codec.packet(input.encoded, input.peer, clock.getAsLong());
                return new Verified(packet, codec.decrypt(packet, input.local, input.identity));
            }, completions::add, (verified, error) -> {
                if (epoch != generation) return;
                incomingChars -= input.encoded.length();
                if (error == null && active(epoch) && stillTrusted(input.peer, input.identity, input.local))
                    accept(input, verified);
            });
        } else if (canPrepare) {
            preferSend = false;
            head.preparing = true;
            byte[] bytes = head.bytes;
            String existing = head.encoded;
            var algorithm = config.aeadAlgorithm;
            worker.submit(() -> {
                // Retry the same signed packet, with a fresh assembly ID for a lost ACK.
                String encoded = existing != null ? existing : codec.encrypt(head.id, head.channel, bytes,
                        head.identity, head.local, algorithm);
                return new Prepared(encoded, new Wire(head.peer, head.identity, head.local, head, encoded));
            }, completions::add, (prepared, error) -> {
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
        if (data.kind() != Kind.DATA) {
            for (Pending request : List.copyOf(pending)) {
                if (request.id.equals(data.transferId()) && request.attempts > 0 && request.local == input.local
                        && request.peer.equalsIgnoreCase(packet.sender())
                        && KeyTrustService.fingerprintPair(request.identity).equals(KeyTrustService.fingerprintPair(input.identity)))
                    finish(request, clock.getAsLong() - request.created >= TRANSFER_TIMEOUT_MS ? Status.TIMEOUT
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
            try { entry.result = Krypt04McgApi.dispatch(data.channel(), packet.sender(), data.bytes()) ? Kind.ACK : Kind.NACK; }
            catch (RuntimeException ignored) { entry.result = Kind.NACK; }
            if (!active(epoch)) return;
            result = entry.result;
        }
        if (data.transferId() != null && receipts.size() + controls.size() + (preparingReceipt ? 1 : 0)
                + (wire != null && wire.request == null ? 1 : 0) < MAX_RECEIPTS)
            receipts.addLast(new Receipt(input.peer, data.transferId(), result, input.identity, input.local));
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
        final List<String> fragments;
        int index;
        Wire(String peer, PublicIdentity identity, LocalKeyMaterial local, Pending request, String encoded) {
            this.peer = peer; this.identity = identity; this.local = local; this.request = request;
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
    private record Receipt(String peer, UUID id, Kind kind, PublicIdentity identity, LocalKeyMaterial local) {}
    private record Verified(EncryptedPacket packet, DataTransferCodec.Data data) {}
    private record Prepared(String encoded, Wire wire) {}
}
