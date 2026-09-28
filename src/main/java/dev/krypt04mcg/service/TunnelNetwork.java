package dev.krypt04mcg.service;

import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.api.KryptSession;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.mixin.ConnectionAccessor;
import io.netty.channel.*;
import io.netty.handler.flow.FlowControlHandler;
import net.minecraft.network.Connection;
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
    private volatile CompletableFuture<TunnelService> ready = CompletableFuture.failedFuture(
            new IOException("Server must advertise krypt04mcg:tunnel"));


    public TunnelNetwork(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                         SessionService sessions, Path root) {
        this.config = config; this.keys = keys; this.trust = trust;
        this.sessions = sessions; this.counters = new TunnelCounters(root);
    }

    public KryptSession attach(KryptSession session) {
        CompletableFuture<TunnelService> connectionReady = ready;
        return session.withStreamSender(frame -> {
            try { connectionReady.get().send(session, frame); }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt(); throw new IOException("Interrupted tunnel connection", e);
            } catch (ExecutionException e) { throw new IOException("Tunnel unavailable", e.getCause()); }
        });
    }

    /** Installation is scheduled on Netty; the caller never waits for I/O. */
    public void connected(Connection connection) {
        Channel next = ((ConnectionAccessor) connection).krypt04mcgChannel();
        if (channel == next) return;
        close();
        channel = next;
        CompletableFuture<TunnelService> connectionReady = new CompletableFuture<>();
        ready = connectionReady;
        next.eventLoop().execute(() -> {
            if (channel != next || !next.isActive()) {
                connectionReady.completeExceptionally(new IOException("Tunnel disconnected during installation"));
                return;
            }

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
            if (channel != next) {
                current.close();
                if (service == current) service = null;
                connectionReady.completeExceptionally(new IOException("Tunnel disconnected during installation"));
                return;
            }
            ChannelPipeline pipeline = next.pipeline();
            // Intercept before bundle assembly as well as before main-thread packet dispatch.
            // Otherwise payloads enclosed in a vanilla bundle would bypass this handler.
            var bundler = pipeline.context(net.minecraft.network.PacketBundlePacker.class);
            String before = bundler == null ? pipeline.context(connection).name() : bundler.name();
            next.config().setAutoRead(false);
            pipeline.addBefore(before, "krypt-tunnel-flow", new FlowControlHandler());
            pipeline.addBefore(before, "krypt-tunnel-input", new TunnelInboundHandler(current::receive, () -> {
                if (channel == next) TunnelNetwork.this.close();
            }));
            connectionReady.complete(current);
            next.read();
        });
    }

    @Override public void close() {
        ready.completeExceptionally(new IOException("Tunnel disconnected"));
        ready = CompletableFuture.failedFuture(new IOException("Tunnel disconnected"));
        Channel previous = channel; channel = null;
        TunnelService old = service; service = null;
        if (old != null) old.close();

        Krypt04McgApi.clearTunnels();
        if (previous != null) previous.eventLoop().execute(() -> {
            var pipeline = previous.pipeline();
            if (pipeline.get("krypt-tunnel-input") != null) pipeline.remove("krypt-tunnel-input");
            if (pipeline.get("krypt-tunnel-flow") != null) pipeline.remove("krypt-tunnel-flow");
            if (previous.isActive()) previous.config().setAutoRead(true);
        });
    }
}
