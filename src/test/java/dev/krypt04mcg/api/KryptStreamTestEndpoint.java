package dev.krypt04mcg.api;

import dev.krypt04mcg.config.Krypt04McgConfig;
import java.util.function.Consumer;

/** Test-only access to independent multiplexers. */
public final class KryptStreamTestEndpoint {
    private final KryptStreamRegistry registry = new KryptStreamRegistry();
    public void configure(Krypt04McgConfig config) { registry.configure(config); }
    public void listen(String channel, Consumer<KryptSocket> listener) { registry.register(channel, listener); }
    public KryptSocket connect(KryptSession session, String channel) { return registry.connect(session, channel); }
    public void receive(KryptSession session, byte[] encoded) { registry.receive(session, encoded); }
    public void clear() { registry.clear(); }
    public int size() { return registry.socketCount(); }
    public static int buffered(KryptSocket socket) { return socket.state().bufferedIncomingBytes(); }
}
