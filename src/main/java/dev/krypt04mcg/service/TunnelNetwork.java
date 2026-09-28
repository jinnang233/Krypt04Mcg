package dev.krypt04mcg.service;

import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.api.KryptSession;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.mixin.ConnectionAccessor;
import dev.krypt04mcg.protocol.TunnelPayload;
import io.netty.channel.*;
import io.netty.handler.flow.FlowControlHandler;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.common.ClientboundCustomPayloadPacket;
import net.minecraft.network.protocol.common.ServerboundCustomPayloadPacket;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.*;

/** Connection-scoped bridge; demand is resumed only after the tunnel I/O worker accepts a frame. */
public final class TunnelNetwork implements AutoCloseable {
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final SessionService sessions;
    private final TunnelCounters counters;
    private volatile TunnelService service;
    private volatile Channel channel;
    private volatile Thread reader;

    public TunnelNetwork(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                         SessionService sessions, Path root) {
        this.config = config; this.keys = keys; this.trust = trust;
        this.sessions = sessions; this.counters = new TunnelCounters(root);
    }

    public KryptSession attach(KryptSession session) {
        TunnelService current = service;
        if (current == null) throw new IllegalStateException("Server must advertise krypt04mcg:tunnel");
        return current.attach(session);
    }

    /** Installation is scheduled on Netty; the caller never waits for I/O. */
    public void connected(Connection connection) {
        close();
        Channel next = ((ConnectionAccessor) connection).krypt04mcgChannel();
        channel = next;
        next.eventLoop().execute(() -> {
            if (channel != next || !next.isActive()) return;
            var input = new ArrayBlockingQueue<Runnable>(1);
            TunnelService current = new TunnelService(config, keys, trust, sessions, counters, payload -> {
                if (!next.isActive()) throw new IOException("Tunnel disconnected");
                CompletableFuture<Void> written = new CompletableFuture<>();
                connection.send(new ServerboundCustomPayloadPacket(payload), future -> {
                    if (future.isSuccess()) written.complete(null);
                    else written.completeExceptionally(future.cause());
                });
                written.get();
            }, Krypt04McgApi::receiveTunnel);
            service = current;
            reader = Thread.ofVirtual().name("krypt-tunnel-decrypt").start(() -> {
                try { while (!Thread.currentThread().isInterrupted()) input.take().run(); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            });
            ChannelPipeline pipeline = next.pipeline();
            String connectionName = pipeline.context(connection).name();
            // FlowControlHandler holds only the already-decoded network read batch. It does not
            // request another socket read until demand arrives, allowing TCP backpressure.
            next.config().setAutoRead(false);
            pipeline.addBefore(connectionName, "krypt-tunnel-flow", new FlowControlHandler());
            pipeline.addBefore(connectionName, "krypt-tunnel-input", new ChannelDuplexHandler() {
                private boolean busy;
                @Override public void read(ChannelHandlerContext ctx) {
                    if (!busy) ctx.read();
                }
                @Override public void channelRead(ChannelHandlerContext ctx, Object message) {
                    if (message instanceof ClientboundCustomPayloadPacket packet
                            && packet.payload() instanceof TunnelPayload payload) {
                        busy = true;
                        input.add(() -> {
                            try { current.receive(payload); }
                            catch (Exception e) {
                                System.getLogger(TunnelNetwork.class.getName()).log(System.Logger.Level.DEBUG,
                                        "Rejected tunnel frame", e);
                            } finally {
                                ctx.executor().execute(() -> {
                                    busy = false;
                                    if (ctx.channel().isActive()) ctx.read();
                                });
                            }
                        });
                    } else {
                        ctx.fireChannelRead(message);
                        ctx.executor().execute(() -> { if (!busy && ctx.channel().isActive()) ctx.read(); });
                    }
                }
                @Override public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                    if (channel == next) TunnelNetwork.this.close();
                    super.channelInactive(ctx);
                }
            });
            next.read();
        });
    }

    @Override public void close() {
        channel = null;
        TunnelService old = service; service = null;
        if (old != null) old.close();
        Thread worker = reader; reader = null;
        if (worker != null) worker.interrupt();
        Krypt04McgApi.clearTunnels();
    }
}
