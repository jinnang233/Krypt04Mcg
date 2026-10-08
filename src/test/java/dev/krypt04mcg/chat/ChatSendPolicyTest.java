package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.ChatSendMode;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class ChatSendPolicyTest {
    @Test void largeChatUsesAvailablePayloadWithoutRelaxingFreshness() {
        for (var mode : ChatSendMode.values()) {
            var plan = ChatSendPolicy.plan(mode, 250, 300, 2048, true);
            assertTrue(plan.customPayload());
            assertEquals(50, plan.delayMillis());
            assertEquals(110_000, plan.queueBudgetMillis());
            assertTrue(2047L * plan.delayMillis() < plan.queueBudgetMillis());
        }
    }

    @Test void unavailableLargePayloadFailsBeforeSending() {
        assertTrue(assertThrows(IllegalStateException.class,
                () -> ChatSendPolicy.plan(ChatSendMode.CHAT, 250, 300, 1000, false))
                .getMessage().contains("custom payload channel"));
        assertThrows(IllegalStateException.class,
                () -> ChatSendPolicy.plan(ChatSendMode.CUSTOM_PAYLOAD, 250, 30, 2048, true));
    }

    @Test void shortMessagesKeepTheirConfiguredTransportAndSafePacing() {
        assertFalse(ChatSendPolicy.plan(ChatSendMode.CHAT, 250, 300, 3, true).customPayload());
        assertEquals(1000, ChatSendPolicy.plan(ChatSendMode.SERVER_COMMAND, 250, 300, 3, true).delayMillis());
        assertEquals(300, ChatSendPolicy.plan(ChatSendMode.CUSTOM_PAYLOAD, 251, 300, 3, true).delayMillis());
    }
}
