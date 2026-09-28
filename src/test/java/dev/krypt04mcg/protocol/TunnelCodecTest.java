package dev.krypt04mcg.protocol;

import static org.junit.jupiter.api.Assertions.*;
import dev.krypt04mcg.api.KryptStreamRegistry.Frame;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.service.SessionService;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TunnelCodecTest {
    @TempDir Path root;

    @Test void encryptRejectsFramesWhoseCompleteEnvelopeExceedsTransportLimit() throws Exception {
        SessionRecord session = new SessionService(root).createLocalSession("Bob", "kem:sig");
        TunnelCodec codec = new TunnelCodec();
        for (var algorithm : AeadAlgorithm.values()) {
            for (byte[] frame : new byte[][] {null, new byte[18400], new byte[TunnelPayload.MAX_BYTES]}) {
                assertThrows(IllegalArgumentException.class, () -> codec.encrypt(session, "Alice", "Bob",
                        UUID.randomUUID(), 0, 0, frame, algorithm));
            }
            byte[] frame = new byte[18000];
            byte[] wire = codec.encrypt(session, "Alice", "Bob", UUID.randomUUID(), 0, 0, frame, algorithm);
            assertTrue(wire.length <= TunnelPayload.MAX_BYTES);
            assertArrayEquals(frame, codec.decrypt(codec.header(wire), session, "Bob", "Alice"));
        }
    }
    @Test void bothAeadsBindPeerEpochStreamLeaseCounterAndCiphertext() throws Exception {
        SessionRecord session = new SessionService(root).createLocalSession("Bob", "kem:sig");
        TunnelCodec codec = new TunnelCodec();
        UUID id = UUID.randomUUID();
        byte[] frame = Frame.data(id, 0, new byte[8192]).encode();
        for (var algorithm : AeadAlgorithm.values()) {
            byte[] wire = codec.encrypt(session, "Alice", "Bob", id, 7, 1, frame, algorithm);
            assertTrue(wire.length < TunnelPayload.MAX_BYTES);
            assertArrayEquals(frame, codec.decrypt(codec.header(wire), session, "Bob", "Alice"));
            assertThrows(Exception.class, () -> codec.decrypt(codec.header(wire), session, "Alice", "Bob"));
            assertThrows(Exception.class, () -> codec.decrypt(codec.header(wire),
                    new SessionService(root.resolve("other")).newSession("Bob", "kem:sig"), "Bob", "Alice"));
            for (int offset : new int[] {0, 16, 23, wire.length - 1}) {
                byte[] changed = wire.clone(); changed[offset] ^= 1;
                assertThrows(Exception.class, () -> codec.decrypt(codec.header(changed), session, "Bob", "Alice"));
            }
            var header = codec.header(wire);
            var p = header.packet();
            var changed = new dev.krypt04mcg.model.EncryptedPacket(p.protocolVersion(), p.type(), p.flags(),
                    p.sender(), p.receiver(), p.timestampMillis(), p.messageId(), p.aadFragmentIndex(), p.aadFragmentTotal(),
                    p.algorithms(), p.nonce(), p.kemCiphertext(), p.ciphertext(), p.signature(), p.sessionId(), 2);
            assertThrows(Exception.class, () -> codec.decrypt(
                    new TunnelCodec.Header(id, 7, changed), session, "Bob", "Alice"));
            assertThrows(Exception.class, () -> codec.header(Arrays.copyOf(wire, 20)));
        }
    }
}

