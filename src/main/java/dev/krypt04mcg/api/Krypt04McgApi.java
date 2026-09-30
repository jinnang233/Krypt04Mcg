package dev.krypt04mcg.api;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

/** Encrypted stream API. Connections/listeners run on the Minecraft client thread. */
public final class Krypt04McgApi {
    private static final ConcurrentHashMap<String, BiConsumer<String, byte[]>> RECEIVERS = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Consumer<KryptSocket>> SOCKETS = new ConcurrentHashMap<>();
    private static volatile Sender sender;
    private static volatile Function<String, KryptSession> connector;
    private static volatile BiFunction<String, String, KryptSocket> opener;
    private Krypt04McgApi() {}
    public static KryptSession connect(String player) {
        var current = connector;
        if (current == null) throw new IllegalStateException("Session API is not initialized");
        return current.apply(Objects.requireNonNull(player));
    }
    public static KryptSocket connect(String player, String channel) {
        validateChannel(channel);
        var current = opener;
        if (current == null) throw new IllegalStateException("Stream API is not initialized");
        return current.apply(Objects.requireNonNull(player), channel);
    }
    public static void registerSocketReceiver(String channel, Consumer<KryptSocket> listener) {
        validateChannel(channel); SOCKETS.put(channel, Objects.requireNonNull(listener));
    }
    public static void unregisterSocketReceiver(String channel) { SOCKETS.remove(channel); }
    /** Convenience write and EOF. There is no delivery receipt; callbacks receive stream portions. */
    public static void send(String channel, byte[] bytes) { send(null, channel, bytes); }
    public static void send(String player, String channel, byte[] bytes) {
        validateChannel(channel); Objects.requireNonNull(bytes);
        var current = sender;
        if (current == null) throw new IllegalStateException("Data API is not initialized");
        current.send(player, channel, bytes);
    }
    public static void registerReceiver(String channel, Consumer<byte[]> receiver) {
        Objects.requireNonNull(receiver); registerReceiver(channel, (peer, bytes) -> receiver.accept(bytes));
    }
    public static void registerReceiver(String channel, BiConsumer<String, byte[]> receiver) {
        validateChannel(channel); RECEIVERS.put(channel, Objects.requireNonNull(receiver));
    }
    public static void unregisterReceiver(String channel) { RECEIVERS.remove(channel); }
    public static void initialize(Sender transport, Function<String, KryptSession> connections,
                                  BiFunction<String, String, KryptSocket> streams) {
        sender = Objects.requireNonNull(transport); connector = Objects.requireNonNull(connections); opener = Objects.requireNonNull(streams);
    }
    /** Internal: listener selection at stream creation. Socket listeners take precedence. */
    public static Consumer<KryptSocket> socketReceiver(String channel) { return SOCKETS.get(channel); }
    public static boolean hasReceiver(String channel) { return RECEIVERS.containsKey(channel); }
    public static boolean dispatch(String channel, String sender, byte[] bytes) {
        var listener = RECEIVERS.get(channel);
        if (listener == null) return false;
        listener.accept(sender, bytes); return true;
    }
    public static void validateChannel(String channel) {
        Objects.requireNonNull(channel);
        if (!channel.matches("[A-Za-z0-9_.:-]{1,256}")) throw new IllegalArgumentException("Invalid application channel");
    }
    @FunctionalInterface public interface Sender { void send(String player, String channel, byte[] bytes); }
}
