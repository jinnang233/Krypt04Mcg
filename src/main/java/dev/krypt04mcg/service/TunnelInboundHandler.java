package dev.krypt04mcg.service;

import dev.krypt04mcg.protocol.TunnelPayload;
import io.netty.channel.*;
import net.minecraft.network.protocol.common.ClientboundCustomPayloadPacket;
import java.util.concurrent.ArrayBlockingQueue;

/** Must follow FlowControlHandler with autoRead disabled. At most one frame is being processed. */
final class TunnelInboundHandler extends ChannelDuplexHandler {
    @FunctionalInterface interface Receiver { void receive(TunnelPayload payload) throws Exception; }
    private final Receiver receiver;
    private final Runnable disconnected;
    private final ArrayBlockingQueue<TunnelPayload> incoming = new ArrayBlockingQueue<>(1);
    private Thread worker;
    private boolean busy;
    private boolean readScheduled;

    TunnelInboundHandler(Receiver receiver, Runnable disconnected) {
        this.receiver = receiver; this.disconnected = disconnected;
    }
    @Override public void handlerAdded(ChannelHandlerContext ctx) {
        worker = Thread.ofVirtual().name("krypt-tunnel-decrypt").start(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    TunnelPayload payload = incoming.take();
                    try { receiver.receive(payload); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                    catch (Exception e) {
                        System.getLogger(TunnelInboundHandler.class.getName()).log(
                                System.Logger.Level.DEBUG, "Rejected tunnel frame", e);
                    } finally {
                        ctx.executor().execute(() -> {
                            busy = false;
                            requestRead(ctx);
                        });
                    }
                }
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        });
    }
    @Override public void read(ChannelHandlerContext ctx) { if (!busy) ctx.read(); }
    @Override public void channelRead(ChannelHandlerContext ctx, Object message) {
        if (message instanceof ClientboundCustomPayloadPacket packet
                && packet.payload() instanceof TunnelPayload payload) {
            busy = true;
            incoming.add(payload); // FlowControlHandler emits only on demand, never while busy.
        } else {
            ctx.fireChannelRead(message);
            requestRead(ctx);
        }
    }
    @Override public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.fireChannelReadComplete();
        // Netty clears unfulfilled flow-control demand at the end of a read cycle.
        // A partial TCP frame may produce no packet at all; waiting for channelRead
        // alone would then leave terrain/keepalive packets queued until disconnect.
        requestRead(ctx);
    }
    private void requestRead(ChannelHandlerContext ctx) {
        if (busy || readScheduled || !ctx.channel().isActive() || ctx.isRemoved()) return;
        readScheduled = true;
        ctx.executor().execute(() -> {
            readScheduled = false;
            if (!busy && ctx.channel().isActive() && !ctx.isRemoved()) ctx.read();
        });
    }
    @Override public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        worker.interrupt(); disconnected.run(); super.channelInactive(ctx);
    }
    @Override public void handlerRemoved(ChannelHandlerContext ctx) {
        worker.interrupt(); incoming.clear();
    }
}
