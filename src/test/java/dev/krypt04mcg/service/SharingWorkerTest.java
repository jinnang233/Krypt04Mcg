package dev.krypt04mcg.service;

import org.junit.jupiter.api.Test;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class SharingWorkerTest {
    @Test void boundsWorkUntilUiCompletionAndRecoversFromFailure() throws Exception {
        try (var worker = new SharingWorker()) {
            var deliveries = new ArrayBlockingQueue<Runnable>(1);
            var result = new AtomicReference<Exception>();
            assertTrue(worker.submit(() -> { throw new IllegalStateException("test"); }, deliveries::add,
                    (value, error) -> result.set(error)));
            Runnable callback = deliveries.poll(5, TimeUnit.SECONDS);
            assertNotNull(callback);
            assertFalse(worker.submit(() -> "queued", deliveries::add, (value, error) -> {}));
            callback.run();
            assertInstanceOf(IllegalStateException.class, result.get());
            assertFalse(worker.busy());
            assertTrue(worker.submit(() -> "ok", deliveries::add, (value, error) -> assertEquals("ok", value)));
            Runnable second = deliveries.poll(5, TimeUnit.SECONDS);
            assertNotNull(second); second.run();
            assertFalse(worker.busy());
        }
    }
}
