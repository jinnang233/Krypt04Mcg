package dev.krypt04mcg.service;

import static org.junit.jupiter.api.Assertions.*;
import dev.krypt04mcg.protocol.TunnelPayload;
import io.netty.channel.*;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.flow.FlowControlHandler;
import net.minecraft.network.protocol.common.ClientboundCustomPayloadPacket;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
class TunnelInboundHandlerTest {
    @Test void blockedConsumerStopsReadDemandWithoutBlockingEventLoop() throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        List<Integer> delivered = new CopyOnWriteArrayList<>();
        var closed = new AtomicBoolean();
        var mainThread = Thread.currentThread();
        var channel = new EmbeddedChannel();
        channel.config().setAutoRead(false);
        channel.pipeline().addLast(new FlowControlHandler());
        channel.pipeline().addLast(new TunnelInboundHandler(payload -> {
            assertNotSame(mainThread, Thread.currentThread());
            delivered.add((int) payload.envelope()[0]);
            entered.countDown(); release.await();
        }, () -> closed.set(true)));
        try {
            channel.read();
            for (int i = 1; i <= 3; i++)
                channel.writeInbound(new ClientboundCustomPayloadPacket(new TunnelPayload("Alice", new byte[] {(byte) i})));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            var eventLoopAlive = new AtomicBoolean();
            channel.eventLoop().execute(() -> eventLoopAlive.set(true));
            channel.runPendingTasks();
            assertTrue(eventLoopAlive.get());
            assertEquals(List.of(1), delivered);
            assertNull(channel.readInbound(), "Tunnel payloads must never reach main-thread dispatch");
            release.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (delivered.size() < 3 && System.nanoTime() < deadline) {
                channel.runPendingTasks(); Thread.sleep(1);
            }
            assertEquals(List.of(1, 2, 3), delivered);
        } finally {
            release.countDown(); channel.finishAndReleaseAll();
        }
        assertTrue(closed.get());
    }

    @Test void ordinaryPacketsKeepTheirOrderAndPassThrough() {
        var channel = new EmbeddedChannel();
        channel.config().setAutoRead(false);
        channel.pipeline().addLast(new FlowControlHandler());
        channel.pipeline().addLast(new TunnelInboundHandler(payload -> fail("No tunnel input"), () -> {}));
        try {
            channel.read(); channel.writeInbound("one", "two");
            channel.runPendingTasks();
            assertEquals("one", channel.readInbound());
            assertEquals("two", channel.readInbound());
        } finally { channel.finishAndReleaseAll(); }
    }
}

