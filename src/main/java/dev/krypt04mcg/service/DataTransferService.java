package dev.krypt04mcg.service;

import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.util.Base64Url;
import java.util.*;
import java.util.function.*;

/** Loader-independent transport state, accessed exclusively on the client thread. */
public final class DataTransferService {
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final BooleanSupplier available;
    private final Consumer<DataPayload> transport;
    private final DataTransferCodec codec = new DataTransferCodec();
    private final OptionalTransferAssembler parts = new OptionalTransferAssembler(FileTransferCodec.MAX_CHUNKS, 4);
    private final Deque<DataPayload> outgoing = new ArrayDeque<>();
    private final Map<String, Long> seen = new HashMap<>();

    public DataTransferService(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                               BooleanSupplier available, Consumer<DataPayload> transport) {
        this.config = config; this.keys = keys; this.trust = trust;
        this.available = available; this.transport = transport;
    }

    public void send(String player, String channel, byte[] data) {
        if (!config.enableDataApi) throw new IllegalStateException("Krypt04Mcg data API is disabled");
        if (!available.getAsBoolean()) throw new IllegalStateException("Data payload relay is unavailable");
        if (!outgoing.isEmpty()) throw new IllegalStateException("Data transfer is busy; retry after it drains");
        String peer = player == null ? config.apiReceiver : player;
        try {
            var identity = trusted(peer);
            var fragments = OptionalTransferAssembler.split(codec.encrypt(channel, data, identity, keys.local(),
                    config.aeadAlgorithm), FileTransferCodec.MAX_CHUNKS);
            for (String fragment : fragments) outgoing.addLast(new DataPayload(peer, fragment, 1));
        } catch (Exception e) { throw new IllegalStateException("Unable to send API data", e); }
    }

    public void receive(DataPayload payload) {
        if (!config.enableDataApi || payload.version() != 1) return;
        try {
            PublicIdentity identity = trusted(payload.peer());
            var assembled = parts.accept(payload.peer(), payload.fragment(), System.currentTimeMillis());
            if (assembled.isEmpty()) return;
            long now = System.currentTimeMillis();
            seen.values().removeIf(expiry -> expiry < now);
            var packet = codec.packet(assembled.get(), payload.peer(), now);
            String id = payload.peer().toLowerCase(Locale.ROOT) + ":" + Base64Url.encode(packet.messageId());
            if (seen.containsKey(id) || seen.size() >= 1024) return;
            var data = codec.decrypt(packet, keys.local(), identity);
            seen.put(id, packet.timestampMillis() + 300000);
            Krypt04McgApi.dispatch(data.channel(), data.bytes());
        } catch (Exception ignored) {
            // Malformed input and third-party callback failures must not crash the client.
        }
    }

    public void tick() {
        if (!config.enableDataApi || !available.getAsBoolean()) {
            outgoing.clear(); parts.clear();
            return;
        }
        parts.expire(System.currentTimeMillis());
        for (int i = 0; i < 4 && !outgoing.isEmpty(); i++) {
            DataPayload payload = outgoing.removeFirst();
            try { trusted(payload.peer()); transport.accept(payload); }
            catch (Exception e) { outgoing.clear(); break; }
        }
    }

    public void clear() { outgoing.clear(); parts.clear(); seen.clear(); }

    private PublicIdentity trusted(String player) throws Exception {
        if (player == null || !player.matches("[A-Za-z0-9_]{1,16}"))
            throw new IllegalArgumentException("Select an API receiver player");
        var identity = keys.findPublicIdentity(player).orElseThrow(() -> new IllegalStateException("Missing public key"));
        if (trust.trustState(player, identity) == TrustState.DISTRUSTED)
            throw new IllegalStateException("Distrusted public key");
        return identity;
    }
}
