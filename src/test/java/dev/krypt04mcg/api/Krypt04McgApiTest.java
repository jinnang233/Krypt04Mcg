package dev.krypt04mcg.api;

import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class Krypt04McgApiTest {
    /**
     * Verifies that sender aware receiver shares replacement and unregistration with legacy receiver.
     */
    @Test void senderAwareReceiverSharesReplacementAndUnregistrationWithLegacyReceiver() {
        var sender = new AtomicReference<String>();
        var received = new AtomicReference<byte[]>();
        byte[] empty = new byte[0];
        Krypt04McgApi.registerReceiver("test:sender", received::set);
        try {
            Krypt04McgApi.registerReceiver("test:sender", (name, data) -> {
                sender.set(name);
                received.set(data);
            });
            Krypt04McgApi.dispatch("other:sender", "Mallory", empty);
            assertNull(sender.get());
            Krypt04McgApi.dispatch("test:sender", "Alice", empty);
            assertEquals("Alice", sender.get());
            assertArrayEquals(empty, received.get());
            Krypt04McgApi.registerReceiver("test:sender", received::set);
            Krypt04McgApi.dispatch("test:sender", "Bob", new byte[]{42});
            assertEquals("Alice", sender.get());
            assertArrayEquals(new byte[]{42}, received.get());
            Krypt04McgApi.registerReceiver("test:sender", (name, data) -> sender.set(name));
            Krypt04McgApi.unregisterReceiver("test:sender");
            Krypt04McgApi.dispatch("test:sender", "Bob", empty);
            assertEquals("Alice", sender.get());
        } finally { Krypt04McgApi.unregisterReceiver("test:sender"); }
    }

    /**
     * Verifies that dispatches only to exact channel and allows replacing and removing receivers.
     */
    @Test void dispatchesOnlyToExactChannelAndAllowsReplacingAndRemovingReceivers() {
        var received = new AtomicReference<byte[]>();
        byte[] input = {0, -1, 42};
        Krypt04McgApi.registerReceiver("test:binary", received::set);
        try {
            Krypt04McgApi.dispatch("other:binary", "Alice", input);
            assertNull(received.get());
            Krypt04McgApi.dispatch("test:binary", "Alice", input);
            assertArrayEquals(input, received.get());
            Krypt04McgApi.registerReceiver("test:binary", bytes -> received.set(new byte[0]));
            Krypt04McgApi.dispatch("test:binary", "Alice", input);
            assertEquals(0, received.get().length);
            Krypt04McgApi.unregisterReceiver("test:binary");
            received.set(null);
            Krypt04McgApi.dispatch("test:binary", "Alice", input);
            assertNull(received.get());
        } finally { Krypt04McgApi.unregisterReceiver("test:binary"); }
    }
}
