package dev.krypt04mcg.api;

import dev.krypt04mcg.config.Krypt04McgConfig;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

/** Message/session APIs use the client thread; socket I/O and socket listeners use workers. */
public final class Krypt04McgApi {
    private static final ConcurrentHashMap<String, BiConsumer<String, byte[]>> RECEIVERS = new ConcurrentHashMap<>();
    private static volatile Sender sender;
    private static volatile Function<String, KryptSession> connector;
    private static final KryptStreamRegistry STREAMS = new KryptStreamRegistry();
    private static volatile Function<KryptSession, KryptSession> tunnel = session -> session;
    private static volatile java.util.function.BooleanSupplier mainThread = () -> false;

    public static void setMainThreadCheck(java.util.function.BooleanSupplier check) { mainThread = check; }
    static void requireIoWorker() throws java.io.IOException {
        if (mainThread.getAsBoolean()) throw new java.io.IOException("Use an I/O worker for KryptSocket reads/writes");
    }

    public static void initializeTunnel(Function<KryptSession, KryptSession> transport) { tunnel = transport; }
    public static void receiveTunnel(KryptSession session, byte[] frame) { STREAMS.receive(session, frame); }
    public static void clearTunnels() { STREAMS.clear(); }

    private Krypt04McgApi() {}

    /** Reuses a valid session or starts the existing authenticated exchange asynchronously. */
    public static KryptSession connect(String player) {
        var current = connector;
        if (current == null) throw new IllegalStateException("Krypt04Mcg session API is not initialized");
        return current.apply(Objects.requireNonNull(player, "player"));
    }

    /** Opens a reliable, ordered byte stream to one application channel. */
    public static KryptSocket connect(String player, String channel) {
        return STREAMS.connect(tunnel.apply(connect(player)), channel);
    }

    /**
     * Registers the listener for remotely opened streams on this exact application channel.
     * The listener runs on the tunnel input worker and must return quickly: hand the socket
     * to an application worker before reading, writing, or waiting for application work.
     */
    public static void registerSocketReceiver(String channel, Consumer<KryptSocket> receiver) {
        STREAMS.register(channel, receiver);
    }

    public static void unregisterSocketReceiver(String channel) { STREAMS.unregister(channel); }

    /** Sends to the default player selected in apiReceiver. */
    public static DataTransfer send(String channel, byte[] data) { return send(null, channel, data); }

    /**
     * Queues a reliable transfer. Disabled/unavailable transport and queue saturation complete the
     * returned handle with a failure status. Null input, wrong thread and uninitialized API throw.
     */
    public static DataTransfer send(String player, String channel, byte[] data) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        Sender current = sender;
        if (current == null) throw new IllegalStateException("Krypt04Mcg is not initialized");
        return current.send(player, channel, data);
    }

    /** Replaces the previous receiver for this exact channel; registration works before initialization. */
    public static void registerReceiver(String channel, Consumer<byte[]> receiver) {
        Objects.requireNonNull(receiver, "receiver");
        registerReceiver(channel, (sender, data) -> receiver.accept(data));
    }

    /**
     * Receives the authenticated sender's player name and opaque application bytes on the client thread.
     * Replaces any receiver registered for this channel, including the single-argument overload.
     */
    public static void registerReceiver(String channel, BiConsumer<String, byte[]> receiver) {
        RECEIVERS.put(Objects.requireNonNull(channel, "channel"), Objects.requireNonNull(receiver, "receiver"));
    }

    public static void unregisterReceiver(String channel) { RECEIVERS.remove(channel); }

    /** Internal loader bridge. */
    public static void initialize(Sender transport) { sender = Objects.requireNonNull(transport); }

    /** Internal loader bridge. */
    public static void initialize(Sender transport, Function<String, KryptSession> connections) {
        initialize(transport, connections, new Krypt04McgConfig());
    }

    /** Internal loader bridge with live stream limits. */
    public static void initialize(Sender transport, Function<String, KryptSession> connections, Krypt04McgConfig config) {
        STREAMS.configure(config);
        initialize(transport);
        connector = Objects.requireNonNull(connections);
    }

    /** Internal: call only after decrypting and authenticating the entire envelope. */
    public static boolean dispatch(String channel, String sender, byte[] data) {
        BiConsumer<String, byte[]> receiver = RECEIVERS.get(channel);
        if (receiver == null) return false;
        receiver.accept(sender, data);
        return true;
    }

    @FunctionalInterface
    public interface Sender { DataTransfer send(String player, String channel, byte[] data); }
}
