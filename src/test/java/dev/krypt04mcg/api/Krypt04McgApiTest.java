package dev.krypt04mcg.api;

import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class Krypt04McgApiTest {
    @Test void dispatchesOnlyToExactChannelAndAllowsReplacingAndRemovingReceivers() {
        var received = new AtomicReference<byte[]>();
        byte[] input = {0, -1, 42};
        Krypt04McgApi.registerReceiver("test:binary", received::set);
        try {
            Krypt04McgApi.dispatch("other:binary", input);
            assertNull(received.get());
            Krypt04McgApi.dispatch("test:binary", input);
            assertArrayEquals(input, received.get());
            Krypt04McgApi.registerReceiver("test:binary", bytes -> received.set(new byte[0]));
            Krypt04McgApi.dispatch("test:binary", input);
            assertEquals(0, received.get().length);
            Krypt04McgApi.unregisterReceiver("test:binary");
            received.set(null);
            Krypt04McgApi.dispatch("test:binary", input);
            assertNull(received.get());
        } finally { Krypt04McgApi.unregisterReceiver("test:binary"); }
    }
}
