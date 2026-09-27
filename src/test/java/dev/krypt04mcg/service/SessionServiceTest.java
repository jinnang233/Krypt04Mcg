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

    @Test void apiSequenceLanesPersistWithoutChangingChatSequenceAndRejectReplays() throws Exception {
        SessionService sessions = new SessionService(tempDir);
        SessionRecord created = sessions.newSession("bob", "kem:sig").withLocalFingerprint("own:keys");
        sessions.save(created);
        assertEquals(0, sessions.reserveApiSend("bob", created.sessionId(), false, 10));
        assertEquals(1, sessions.reserveApiSend("bob", created.sessionId(), true, 0));
        sessions.recordApiReceived("bob", created.sessionId(), 4, false, 20); // A failed encryption may leave a gap.
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
        assertEquals(2, restored.messageCount());
        assertEquals(12, restored.bytesUsed());
        assertEquals(2, restored.apiMessageCount()); // ACKs do not consume either rotation budget.
        assertEquals(30, restored.apiBytesUsed());
        sessions.recordApiReceived("bob", created.sessionId(), 0, false, 0);
        sessions.recordApiReceived("bob", created.sessionId(), 2, false, 0);
        sessions.recordApiReceived("bob", created.sessionId(), 1, true, 0);
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 4, false, 0));
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 2, false, 0));
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 1, true, 0));
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 5, false, 0));
        sessions.recordApiReceived("bob", created.sessionId(), 200, false, 0);
        assertThrows(java.io.IOException.class, () -> sessions.recordApiReceived("bob", created.sessionId(), 20, false, 0));
        assertThrows(java.io.IOException.class, () -> sessions.reserveApiSend("bob", "different-epoch", false, 0));
    }

    @Test void legacySessionWithoutReplayBitmapsKeepsOldSequencesRejected() throws Exception {
        SessionService sessions = new SessionService(tempDir);
        SessionRecord created = sessions.newSession("bob", "kem:sig").withLocalFingerprint("own:keys");
        SessionRecord legacy = new SessionRecord(created.peer(), created.peerFingerprint(), created.sessionId(),
                created.createdAt(), created.lastUsedAt(), created.secret(), 0, 0, 0, 0,
                created.localFingerprint(), 0, 3, 0, 0, 0, 0, null, null);
        sessions.save(legacy);

        assertThrows(java.io.IOException.class,
                () -> sessions.recordApiReceived("bob", created.sessionId(), 0, false, 0));
        sessions.recordApiReceived("bob", created.sessionId(), 6, false, 1);
        SessionRecord migrated = sessions.find("bob").orElseThrow();
        assertEquals(4, migrated.nextApiReceiveSequence());
        assertEquals(Long.valueOf(15), migrated.apiReceiveWindow());
    }
}
