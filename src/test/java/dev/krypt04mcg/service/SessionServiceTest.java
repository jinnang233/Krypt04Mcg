package dev.krypt04mcg.service;

import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.SensitiveFileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SessionServiceTest {
    @TempDir
    private Path tempDir;

    /**
     * Verifies that legacy records migrate without losing counters and clear retains epoch.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void legacyRecordsMigrateWithoutLosingCountersAndClearRetainsEpoch() throws Exception {
        var sessions = new SessionService(tempDir);
        var fresh = sessions.newSession("bob", "kem:sig");
        var legacy = new SessionRecord(fresh.peer(), fresh.peerFingerprint(), fresh.sessionId(), fresh.createdAt(),
                fresh.lastUsedAt(), fresh.secret(), 3, 17, 5, 7).withLocalFingerprint("own:keys");
        var file = tempDir.resolve("sessions/bob.json");
        Files.createDirectories(file.getParent());
        Files.writeString(file, dev.krypt04mcg.util.JsonSupport.prettyGson().toJson(legacy));
        assertEquals(java.util.List.of(legacy), sessions.list());
        assertTrue(SensitiveFileStore.isEncrypted(file));
        assertEquals(legacy, new SessionService(tempDir).find("bob").orElseThrow());
        var first = sessions.reserveHandshake("bob");
        assertEquals(legacy.sessionId(), first.previousSessionId());
        sessions.clear("bob");
        var restarted = new SessionService(tempDir);
        assertTrue(restarted.find("bob").isEmpty());
        var next = restarted.reserveHandshake("bob");
        assertEquals(first.previousSessionId(), next.previousSessionId());
        assertTrue(next.requestEpoch() > first.requestEpoch());
    }

    /**
     * Verifies that session secrets are encrypted and sequences advance atomically.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void sessionSecretsAreEncryptedAndSequencesAdvanceAtomically() throws Exception {
        SessionService sessions = new SessionService(tempDir);
        SessionRecord created = sessions.createLocalSession("bob", "kem:sig");
        Path file = tempDir.resolve("sessions").resolve("bob.json");

        assertTrue(SensitiveFileStore.isEncrypted(file));
        assertFalse(new String(Files.readAllBytes(file), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains(created.secret()));

        sessions.recordSentMessage("bob", 0, 5);
        sessions.recordReceivedMessage("bob", created.sessionId(), 0, 7);
        SessionRecord updated = sessions.find("bob").orElseThrow();
        assertEquals(1, updated.nextSendSequence());
        assertEquals(1, updated.nextReceiveSequence());
        assertEquals(2, updated.messageCount());
        assertEquals(12, updated.bytesUsed());
    }

    /**
     * Verifies that api sequence lanes persist without changing chat sequence and reject replays.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void apiSequenceLanesPersistWithoutChangingChatSequenceAndRejectReplays() throws Exception {
        SessionService sessions = new SessionService(tempDir);
        SessionRecord created = sessions.newSession("bob", "kem:sig").withLocalFingerprint("own:keys");
        sessions.save(created);
        assertEquals(0, sessions.reserveApiSend("bob", created.sessionId(), false, 10));
        assertEquals(1, sessions.reserveApiSend("bob", created.sessionId(), true, 0));
        sessions.recordApiReceived("bob", created.sessionId(), 4, false, 20);
        // A failed encryption may leave a gap.
        sessions.recordApiReceived("bob", created.sessionId(), 3, true, 0);
        sessions.recordSentMessage("bob", 0, 5);
        sessions.recordReceivedMessage("bob", created.sessionId(), 0, 7);
        SessionRecord restored = new SessionService(tempDir).find("bob").orElseThrow();
        assertEquals("own:keys", restored.localFingerprint());
        assertEquals(1, restored.nextApiSendSequence());
        assertEquals(3, restored.nextApiReceiveSequence());
        assertEquals(1, restored.nextApiControlSendSequence());
        assertEquals(2, restored.nextApiControlReceiveSequence());
        assertEquals(1, restored.nextSendSequence());
        assertEquals(1, restored.nextReceiveSequence());
        assertEquals(4, restored.messageCount());
        // ACKs do not consume the application rotation budget.
        assertEquals(42, restored.bytesUsed());
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 4, false, 0));
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 2, false, 0));
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 5, false, 0));
        assertThrows(java.io.IOException.class, () -> sessions.reserveApiSend("bob", "different-epoch", false, 0));
    }
}
