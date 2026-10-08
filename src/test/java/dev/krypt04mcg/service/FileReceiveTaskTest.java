package dev.krypt04mcg.service;

import dev.krypt04mcg.api.KryptSocket;
import dev.krypt04mcg.protocol.FileStreamCodec.FileData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class FileReceiveTaskTest {
    @Test void slowNonemptyProgressCannotExtendDeadlineAndWorkerCanBeReused() throws Exception {
        var clock = new AtomicLong();
        var socket = socket();
        var task = new FileReceiveTask(socket, clock::get);
        socket.accept(header(100));
        try (var worker = new SharingWorker()) {
            var completions = new ArrayBlockingQueue<Runnable>(1);
            var failure = new AtomicReference<Exception>();
            assertTrue(worker.submit(task::read, completions::add, (data, error) -> failure.set(error)));
            for (int second : new int[]{59, 118}) {
                clock.set(TimeUnit.SECONDS.toNanos(second));
                socket.accept(new byte[]{42});
                assertFalse(task.expire());
                assertTrue(worker.busy());
                assertTrue(completions.isEmpty());
            }
            clock.set(TimeUnit.SECONDS.toNanos(120));
            socket.accept(new byte[]{42});
            assertTrue(task.expire());
            assertTrue(socket.isFailed());
            complete(completions);
            assertInstanceOf(IOException.class, failure.get());
            assertFalse(worker.busy());

            var next = socket();
            next.accept(header(0)); next.remoteEnd();
            var result = new AtomicReference<FileData>();
            var nextTask = new FileReceiveTask(next, clock::get);
            assertTrue(worker.submit(nextTask::read, completions::add, (data, error) -> {
                assertNull(error); result.set(data);
            }));
            complete(completions);
            assertEquals("file.bin", result.get().name());
            assertArrayEquals(new byte[0], result.get().data());
            assertFalse(worker.busy());
        }
    }

    @Test void completeContentsWithoutAuthenticatedEofStillExpire() throws Exception {
        var clock = new AtomicLong();
        var socket = socket();
        socket.accept(header(0));
        var task = new FileReceiveTask(socket, clock::get);
        try (var worker = new SharingWorker()) {
            var completions = new ArrayBlockingQueue<Runnable>(1);
            var failure = new AtomicReference<Exception>();
            assertTrue(worker.submit(task::read, completions::add, (data, error) -> failure.set(error)));
            assertTrue(completions.isEmpty());
            clock.set(TimeUnit.MINUTES.toNanos(2));
            assertTrue(task.expire());
            complete(completions);
            assertInstanceOf(IOException.class, failure.get());
            assertFalse(worker.busy());
        }
    }

    @Test void lateCompleteInputIsRejectedEvenBeforeNextTick() throws Exception {
        var clock = new AtomicLong();
        var socket = socket();
        var task = new FileReceiveTask(socket, clock::get);
        clock.set(TimeUnit.MINUTES.toNanos(2));
        socket.accept(header(0)); socket.remoteEnd();
        assertThrows(IOException.class, task::read);
        assertTrue(socket.isFailed());
    }

    @Test void successfulReadIsNotExpiredWhileItsUiCallbackWaits() throws Exception {
        var clock = new AtomicLong();
        var socket = socket();
        var task = new FileReceiveTask(socket, clock::get);
        socket.accept(header(0)); socket.remoteEnd();
        try (var worker = new SharingWorker()) {
            var completions = new ArrayBlockingQueue<Runnable>(1);
            var result = new AtomicReference<FileData>();
            assertTrue(worker.submit(task::read, completions::add, (data, error) -> {
                assertNull(error); result.set(data);
            }));
            Runnable completion = completions.poll(5, TimeUnit.SECONDS);
            assertNotNull(completion);
            clock.set(TimeUnit.MINUTES.toNanos(3));
            assertFalse(task.expire());
            assertFalse(socket.isFailed());
            completion.run();
            assertEquals("file.bin", result.get().name());
            assertFalse(worker.busy());
        }
    }

    @Test void cancellationUnblocksTheReaderAndReleasesTheWorker() throws Exception {
        var socket = socket();
        var task = new FileReceiveTask(socket);
        try (var worker = new SharingWorker()) {
            var completions = new ArrayBlockingQueue<Runnable>(1);
            var failure = new AtomicReference<Exception>();
            assertTrue(worker.submit(task::read, completions::add, (data, error) -> failure.set(error)));
            task.cancel();
            complete(completions);
            assertInstanceOf(IOException.class, failure.get());
            assertFalse(worker.busy());
        }
    }

    private static KryptSocket socket() { return new KryptSocket("Bob", "krypt04mcg_file:stream", UUID.randomUUID()); }

    private static byte[] header(int size) throws IOException {
        var bytes = new ByteArrayOutputStream();
        var out = new DataOutputStream(bytes);
        out.writeUTF("file.bin"); out.writeInt(size);
        return bytes.toByteArray();
    }

    private static void complete(ArrayBlockingQueue<Runnable> completions) throws InterruptedException {
        Runnable completion = completions.poll(5, TimeUnit.SECONDS);
        assertNotNull(completion);
        completion.run();
    }
}
