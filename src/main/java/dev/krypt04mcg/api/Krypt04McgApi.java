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
    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private Krypt04McgApi() {}
    /**
     * Requests a peer API session or named encrypted stream through the installed client-thread
     * implementation. The returned handle may require readiness negotiation; initialization and channel
     * validation precede delegation.
     *
     * @param player the player supplied to this operation
     * @return the result described above
     */
    public static KryptSession connect(String player) {
        var current = connector;
        if (current == null) throw new IllegalStateException("Session API is not initialized");
        return current.apply(Objects.requireNonNull(player));
    }
    /**
     * Requests a peer API session or named encrypted stream through the installed client-thread
     * implementation. The returned handle may require readiness negotiation; initialization and channel
     * validation precede delegation.
     *
     * @param player the player supplied to this operation
     * @param channel the business or transport channel identifier
     * @return the result described above
     */
    public static KryptSocket connect(String player, String channel) {
        validateChannel(channel);
        var current = opener;
        if (current == null) throw new IllegalStateException("Stream API is not initialized");
        return current.apply(Objects.requireNonNull(player), channel);
    }
    /**
     * Registers a listener for accepted encrypted sockets on a validated business channel. Application
     * code must handle stream lifetime, partial reads and backpressure rather than assuming one socket
     * callback contains a complete message.
     *
     * @param channel the business or transport channel identifier
     * @param listener the listener supplied to this operation
     */
    public static void registerSocketReceiver(String channel, Consumer<KryptSocket> listener) {
        validateChannel(channel); SOCKETS.put(channel, Objects.requireNonNull(listener));
    }
    /**
     * Removes socket receiver from the public encrypted-stream API.
     *
     * @param channel the business or transport channel identifier
     */
    public static void unregisterSocketReceiver(String channel) { SOCKETS.remove(channel); }
    /**
     * Delegates a convenience payload write plus EOF to the initialized encrypted-stream implementation.
     * Receivers observe stream portions rather than an atomic message, and there is no delivery receipt.
     * Larger data must use the socket API incrementally with backpressure.
     *
     * @param channel the business or transport channel identifier
     * @param bytes the bytes supplied to this operation
     */
    public static void send(String channel, byte[] bytes) { send(null, channel, bytes); }
    /**
     * Delegates a convenience payload write plus EOF to the initialized encrypted-stream implementation.
     * Receivers observe stream portions rather than an atomic message, and there is no delivery receipt.
     * Larger data must use the socket API incrementally with backpressure.
     *
     * @param player the player supplied to this operation
     * @param channel the business or transport channel identifier
     * @param bytes the bytes supplied to this operation
     */
    public static void send(String player, String channel, byte[] bytes) {
        validateChannel(channel); Objects.requireNonNull(bytes);
        var current = sender;
        if (current == null) throw new IllegalStateException("Data API is not initialized");
        current.send(player, channel, bytes);
    }
    /**
     * Registers the application callback for a validated business channel. The callback consumes already
     * authenticated stream portions supplied by the client service; registration is not a server-side
     * network channel allocation.
     *
     * @param channel the business or transport channel identifier
     * @param receiver the intended recipient associated with this operation
     */
    public static void registerReceiver(String channel, Consumer<byte[]> receiver) {
        Objects.requireNonNull(receiver); registerReceiver(channel, (peer, bytes) -> receiver.accept(bytes));
    }
    /**
     * Registers the application callback for a validated business channel. The callback consumes already
     * authenticated stream portions supplied by the client service; registration is not a server-side
     * network channel allocation.
     *
     * @param channel the business or transport channel identifier
     * @param receiver the intended recipient associated with this operation
     */
    public static void registerReceiver(String channel, BiConsumer<String, byte[]> receiver) {
        validateChannel(channel); RECEIVERS.put(channel, Objects.requireNonNull(receiver));
    }
    /**
     * Removes receiver from the public encrypted-stream API.
     *
     * @param channel the business or transport channel identifier
     */
    public static void unregisterReceiver(String channel) { RECEIVERS.remove(channel); }
    /**
     * Installs the client-thread session connector, stream opener and convenience sender used by the
     * public API. Consumers must use these delegates within the implementation thread/lifecycle contract.
     *
     * @param transport the transport supplied to this operation
     * @param connections the connections supplied to this operation
     * @param streams the streams supplied to this operation
     */
    public static void initialize(Sender transport, Function<String, KryptSession> connections,
                                  BiFunction<String, String, KryptSocket> streams) {
        sender = Objects.requireNonNull(transport); connector = Objects.requireNonNull(connections); opener = Objects.requireNonNull(streams);
    }
    /**
     * Internal: listener selection at stream creation. Socket listeners take precedence.
     *
     * @param channel the business or transport channel identifier
     * @return the result described above
     */
    public static Consumer<KryptSocket> socketReceiver(String channel) { return SOCKETS.get(channel); }
    /**
     * Reports whether the public encrypted-stream API has receiver.
     *
     * @param channel the business or transport channel identifier
     * @return whether the condition or operation described above succeeds
     */
    public static boolean hasReceiver(String channel) { return RECEIVERS.containsKey(channel); }
    /**
     * Returns the recorded false for the public encrypted-stream API.
     *
     * @param channel the business or transport channel identifier
     * @param sender the sender or source associated with this operation
     * @param bytes the bytes supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public static boolean dispatch(String channel, String sender, byte[] bytes) {
        var listener = RECEIVERS.get(channel);
        if (listener == null) return false;
        listener.accept(sender, bytes); return true;
    }
    /**
     * Checks the API business-channel identifier against its length/grammar contract. Channel syntax
     * validity does not establish peer identity, stream authorization or application trust.
     *
     * @param channel the business or transport channel identifier
     */
    public static void validateChannel(String channel) {
        Objects.requireNonNull(channel);
        if (!channel.matches("[A-Za-z0-9_.:-]{1,256}")) throw new IllegalArgumentException("Invalid application channel");
    }
    @FunctionalInterface public interface Sender {
        /**
         * Delegates a convenience payload write plus EOF to the initialized encrypted-stream implementation.
         * Receivers observe stream portions rather than an atomic message, and there is no delivery receipt.
         * Larger data must use the socket API incrementally with backpressure.
         *
         * @param player the player supplied to this operation
         * @param channel the business or transport channel identifier
         * @param bytes the bytes supplied to this operation
         */
        void send(String player, String channel, byte[] bytes); }
}
