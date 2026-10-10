package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.ChatSendMode;

/** Fits the send into the fixed assembly and authenticated freshness windows. */
final class ChatSendPolicy {
    record Plan(boolean customPayload, int delayMillis, long queueBudgetMillis) {}

    /**
     * Performs the plan operation for the chat transport admission policy.
     *
     * @param mode the mode supplied to this operation
     * @param configuredDelay the configured delay supplied to this operation
     * @param maxPacketAgeSeconds the max packet age seconds supplied to this operation
     * @param fragments the fragments supplied to this operation
     * @param customPayloadAvailable the custom payload available supplied to this operation
     * @return the result described above
     */
    static Plan plan(ChatSendMode mode, int configuredDelay, int maxPacketAgeSeconds,
                     int fragments, boolean customPayloadAvailable) {
        long budget = Math.min(110_000L, Math.clamp(maxPacketAgeSeconds, 30, 3600) * 1000L - 15_000L);
        int delay = Math.clamp(configuredDelay, 0, 60_000);
        boolean custom = mode == ChatSendMode.CUSTOM_PAYLOAD;
        if (!custom) delay = Math.max(1000, delay);
        // The client pumps once per 50 ms tick; round upward for admission estimates.
        delay = ((delay + 49) / 50) * 50;
        if ((long) Math.max(0, fragments - 1) * Math.max(50, delay) >= budget) {
            if (!customPayloadAvailable) {
                throw new IllegalStateException("Large encrypted chat needs the Krypt04Mcg custom payload channel; "
                        + "update the server relay or send a shorter message");
            }
            custom = true;
            delay = 50;
        }
        if ((long) Math.max(0, fragments - 1) * Math.max(50, delay) >= budget) {
            throw new IllegalStateException("Encrypted chat cannot finish within the configured packet age window");
        }
        return new Plan(custom, delay, budget);
    }

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private ChatSendPolicy() {}
}
