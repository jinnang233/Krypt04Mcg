package dev.krypt04mcg.api;

import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TunnelFramingTest {
    @Test void dataIsOneSmallFrameWithoutSecondaryFragmentation() {
        UUID id = UUID.randomUUID();
        byte[] data = new byte[8192];
        var frame = KryptStreamRegistry.Frame.decode(KryptStreamRegistry.Frame.data(id, 0, data).encode());
        assertArrayEquals(data, frame.data);
        assertEquals(8192, KryptSocket.CHUNK_BYTES);
        assertThrows(IllegalArgumentException.class, () -> KryptStreamRegistry.Frame.decode(
                KryptStreamRegistry.Frame.data(id, 0, new byte[8193]).encode()));
    }
}
