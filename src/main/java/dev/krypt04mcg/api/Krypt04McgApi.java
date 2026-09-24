package dev.krypt04mcg.api;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/** Client API. Send on the Minecraft client thread; receivers run on that thread too. */
public final class Krypt04McgApi {
    private static final ConcurrentHashMap<String, Consumer<byte[]>> RECEIVERS = new ConcurrentHashMap<>();
    private static volatile Sender sender;

    private Krypt04McgApi() {}

    /** Sends to the default player selected in apiReceiver. */
    public static void send(String channel, byte[] data) { send(null, channel, data); }

    /** Requires an enabled API, a connected relay and the player's imported public key. */
    public static void send(String player, String channel, byte[] data) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(data, "data");
        Sender current = sender;
        if (current == null) throw new IllegalStateException("Krypt04Mcg is not initialized");
        current.send(player, channel, data);
    }

    /** Replaces the previous receiver for this exact channel; registration works before initialization. */
    public static void registerReceiver(String channel, Consumer<byte[]> receiver) {
        RECEIVERS.put(Objects.requireNonNull(channel, "channel"), Objects.requireNonNull(receiver, "receiver"));
    }

    public static void unregisterReceiver(String channel) { RECEIVERS.remove(channel); }

    /** Internal loader bridge. */
    public static void initialize(Sender transport) { sender = Objects.requireNonNull(transport); }

    /** Internal: call only after decrypting and authenticating the entire envelope. */
    public static void dispatch(String channel, byte[] data) {
        Consumer<byte[]> receiver = RECEIVERS.get(channel);
        if (receiver != null) receiver.accept(data);
    }

    @FunctionalInterface
    public interface Sender { void send(String player, String channel, byte[] data); }
}
