package dev.krypt04mcg.config;

import dev.krypt04mcg.chat.ChatConversationStore;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.service.SentMessageCacheService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuntimeLimitsTest {
    @TempDir Path root;

    @Test void jsonCreatesDefaultsLoadsOverridesAndPreservesMalformedInput() throws Exception {
        Path file = root.resolve("config/krypt04mcg.json");
        assertEquals(300, ConfigFileStore.load(file).maxConversationMessages());
        assertTrue(Files.exists(file));
        Files.writeString(file, "{\"maxConversationMessages\":2,\"enableDataApi\":true,\"maxDataAttempts\":-1,\"dataAckTimeoutSeconds\":0}");
        var config = ConfigFileStore.load(file);
        assertEquals(2, config.maxConversationMessages());
        assertTrue(config.enableDataApi);
        assertEquals(1, config.maxDataAttempts());
        assertEquals(61, config.dataAckTimeoutSeconds());
        assertEquals(128, config.maxReassemblyMessages());
        config.maxDataQueuedMiB = Integer.MAX_VALUE;
        assertEquals(4096, config.maxDataQueuedMiB());
        Files.writeString(file, "{bad json");
        assertThrows(java.io.IOException.class, () -> ConfigFileStore.load(file));
        assertEquals("{bad json", Files.readString(file));
        Files.writeString(file, "null");
        assertThrows(java.io.IOException.class, () -> ConfigFileStore.load(file));
    }

    @Test void cachesUseConfiguredLimitsAndObserveChanges() throws Exception {
        var config = new Krypt04McgConfig();
        config.maxConversationMessages = 2;
        var history = new ChatConversationStore(root, () -> true, config::maxConversationMessages);
        history.incoming("Alice", "one");
        history.incoming("Alice", "two");
        history.incoming("Alice", "three");
        assertEquals(List.of("two", "three"), history.messagesFor("Alice").stream().map(ChatConversationStore.Entry::message).toList());
        config.maxConversationMessages = 1;
        history.incoming("Alice", "four");
        assertEquals(1, new ChatConversationStore(root).messagesFor("Alice").size());
        var sent = new SentMessageCacheService(root, config::maxCachedSentMessages);
        config.maxCachedSentMessages = 1;
        sent.remember("first", "Alice", List.of("first"));
        // Avoid equal timestamps when choosing the oldest entry on coarse clocks.
        Thread.sleep(10);
        sent.remember("second", "Alice", List.of("second"));
        assertTrue(sent.find("first").isEmpty());
        assertTrue(sent.find("second").isPresent());
    }

    @Test void fragmentLimitsApplyToSendAndReceiveAndCanChangeLive() {
        var config = new Krypt04McgConfig();
        config.maxFragmentsPerMessage = 2;
        config.maxReassemblyMessages = 1;
        var sender = new FragmentService(config);
        var receiver = new FragmentReassembler(config);
        assertThrows(IllegalArgumentException.class, () -> sender.fragment(new byte[500], new byte[16], 100));
        assertThrows(IllegalArgumentException.class, () -> receiver.accept(new Fragment("a", 0, 3, "AA")));
        receiver.accept(new Fragment("a", 0, 2, "AA"));
        receiver.accept(new Fragment("b", 0, 2, "AA"));
        assertTrue(receiver.progress("a").isEmpty());
        config.maxFragmentsPerMessage = 20;
        assertTrue(sender.fragment(new byte[500], new byte[16], 100).size() > 2);
        assertDoesNotThrow(() -> receiver.accept(new Fragment("c", 0, 3, "AA")));
    }
}
