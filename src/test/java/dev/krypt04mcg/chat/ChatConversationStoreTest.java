package dev.krypt04mcg.chat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import dev.krypt04mcg.util.SensitiveFileStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ChatConversationStoreTest {
    @TempDir
    private Path tempDir;

    @Test
    void persistsAndReloadsConversationHistory() throws Exception {
        ChatConversationStore first = new ChatConversationStore(tempDir);
        first.outgoing("alice", "hello alice");
        first.incoming("bob", "hello back");
        first.outgoingGroup("team", "hello team");
        Path history = tempDir.resolve("cache").resolve("conversations.json");
        assertTrue(SensitiveFileStore.isEncrypted(history));
        assertTrue(!new String(Files.readAllBytes(history), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains("hello alice"));

        ChatConversationStore second = new ChatConversationStore(tempDir);

        assertEquals("hello alice", second.messagesFor("alice").getFirst().message());
        assertEquals("hello back", second.messagesFor("bob").getFirst().message());
        assertEquals("hello team", second.messagesForGroup("team").getFirst().message());
        assertEquals(0, second.peers().stream().filter("team"::equalsIgnoreCase).count());
        assertEquals(1, second.groups().stream().filter("team"::equalsIgnoreCase).count());
    }

    @Test
    void keepsPlayerAndGroupHistoriesSeparateWhenNamesMatch() {
        ChatConversationStore store = new ChatConversationStore(tempDir);

        store.outgoing("party", "player message");
        store.outgoingGroup("party", "group message");

        assertEquals("player message", store.messagesFor("party").getFirst().message());
        assertEquals("group message", store.messagesForGroup("party").getFirst().message());
    }

    @Test
    void trimsHistoryToBoundedCache() {
        ChatConversationStore store = new ChatConversationStore(tempDir);

        for (int i = 0; i < 350; i++) {
            store.outgoing("alice", "message-" + i);
        }

        ChatConversationStore reloaded = new ChatConversationStore(tempDir);
        assertEquals(300, reloaded.messagesFor("alice").size());
        assertEquals("message-50", reloaded.messagesFor("alice").getFirst().message());
        assertEquals("message-349", reloaded.messagesFor("alice").getLast().message());
    }

    @Test
    void ignoresCorruptHistoryFile() throws Exception {
        Path file = tempDir.resolve("cache").resolve("conversations.json");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "{not valid json");

        ChatConversationStore store = new ChatConversationStore(tempDir);

        assertTrue(store.peers().isEmpty());
        assertTrue(store.groups().isEmpty());
    }

    @Test
    void disabledHistoryKeepsLiveMessagesWithoutLoadingOrSavingHistory() throws Exception {
        ChatConversationStore enabled = new ChatConversationStore(tempDir);
        enabled.outgoing("alice", "persisted");

        ChatConversationStore disabled = new ChatConversationStore(tempDir, false);
        byte[] savedHistory = Files.readAllBytes(tempDir.resolve("cache/conversations.json"));
        disabled.incoming("bob", "收到的消息");
        disabled.outgoing("bob", "not persisted");
        disabled.outgoingGroup("team", "not persisted either");

        assertTrue(disabled.messagesFor("alice").isEmpty());
        assertEquals("收到的消息", disabled.messagesFor("BOB").getFirst().message());
        assertTrue(!disabled.messagesFor("bob").getFirst().outgoing());
        assertEquals("not persisted", disabled.messagesFor("bob").getLast().message());
        assertEquals("not persisted either", disabled.messagesForGroup("team").getFirst().message());
        assertEquals(java.util.List.of("bob"), disabled.peers());
        org.junit.jupiter.api.Assertions.assertArrayEquals(savedHistory,
                Files.readAllBytes(tempDir.resolve("cache/conversations.json")));

        ChatConversationStore reloaded = new ChatConversationStore(tempDir);
        assertEquals("persisted", reloaded.messagesFor("alice").getFirst().message());
        assertTrue(reloaded.messagesFor("bob").isEmpty());
        assertTrue(reloaded.messagesForGroup("team").isEmpty());
    }

    @Test
    void disabledHistoryRemainsBoundedWithoutCreatingFiles() {
        ChatConversationStore store = new ChatConversationStore(tempDir, false);
        for (int i = 0; i < 350; i++) {
            store.incoming("alice", "message-" + i);
        }
        assertEquals(300, store.messagesFor("alice").size());
        assertEquals("message-50", store.messagesFor("alice").getFirst().message());
        assertTrue(Files.notExists(tempDir.resolve("cache/conversations.json")));
        assertTrue(new ChatConversationStore(tempDir, false).peers().isEmpty());
    }

    @Test
    void enablingHistoryPlacesSavedMessagesBeforeLiveMessages() {
        new ChatConversationStore(tempDir).incoming("alice", "saved");
        var enabled = new java.util.concurrent.atomic.AtomicBoolean(false);
        ChatConversationStore store = new ChatConversationStore(tempDir, enabled::get);
        store.incoming("alice", "live");
        enabled.set(true);
        store.incoming("alice", "new");
        assertEquals(java.util.List.of("saved", "live", "new"), store.messagesFor("alice").stream()
                .map(ChatConversationStore.Entry::message).toList());
        assertEquals(store.messagesFor("alice"), new ChatConversationStore(tempDir).messagesFor("alice"));
    }
}
