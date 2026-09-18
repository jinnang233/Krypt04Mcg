package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.fragment.FragmentService;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class ReceiveRegexTest {
    @Test void invalidReceiveRegexDoesNotEscapeChatCallbacks() {
        var config = new Krypt04McgConfig();
        config.receiveRegexMode = true;
        config.hideEncryptedRawMessage = true;
        var handler = new ChatReceiveHandler(config, null, null, null, null,
                new FragmentService(), null, null, null, null, null,
                message -> fail("Malformed local filter must reject before packet processing"), null);
        String fragment = "[KRYPT04MCG] 00000000000000000000000000000000 0 1 YQ";
        for (String invalid : new String[]{"[", null}) {
            config.receiveRegex = invalid;
            assertFalse(handler.shouldHide(fragment));
            assertDoesNotThrow(() -> handler.handle("bob", fragment));
        }
        config.receiveRegex = ".*";
        assertTrue(handler.shouldHide(fragment));
    }
}
