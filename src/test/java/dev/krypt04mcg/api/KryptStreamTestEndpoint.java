package dev.krypt04mcg.api;

import java.util.function.Consumer;

/** Test-only bridge for wiring two package-private stream registries through real services. */
public final class KryptStreamTestEndpoint {
    private final KryptStreamRegistry registry = new KryptStreamRegistry();

    public void listen(String channel, Consumer<KryptSocket> listener) { registry.register(channel, listener); }
    public KryptSocket connect(KryptSession session, String channel) { return registry.connect(session, channel); }
    public void receive(String sender, byte[] encoded) { registry.receive(sender, encoded); }
    public static String wireChannel() { return KryptStreamRegistry.WIRE_CHANNEL; }

    public static SocketStats stats(KryptSocket socket) {
        KryptSocket.State state = socket.state();
        return new SocketStats(state.queuedChunks(), state.inFlightChunks(),
                state.completedOutOfOrderChunks(), state.bufferedIncomingBytes());
    }

    public record SocketStats(int queuedChunks, int inFlightChunks,
                              int completedOutOfOrderChunks, int bufferedIncomingBytes) {}
}
