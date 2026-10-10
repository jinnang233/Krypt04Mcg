package dev.krypt04mcg.client;

import net.minecraft.client.resources.language.I18n;

public final class ClientMessages {
    private static final String DEFAULT_MESSAGE_PREFIX = "[Krypt04Mcg]";
    private static volatile String messagePrefix = DEFAULT_MESSAGE_PREFIX;

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private ClientMessages() {
    }

    /**
     * Updates the message prefix used by the client messages.
     *
     * @param configuredPrefix the configured prefix supplied to this operation
     */
    public static void setMessagePrefix(String configuredPrefix) {
        messagePrefix = configuredPrefix == null ? DEFAULT_MESSAGE_PREFIX : configuredPrefix;
    }

    /**
     * Returns the recorded message prefix for the client messages.
     *
     * @return the result described above
     */
    public static String messagePrefix() {
        return messagePrefix;
    }

    /**
     * Performs the message prefix with space operation for the client messages.
     *
     * @return the result described above
     */
    public static String messagePrefixWithSpace() {
        return messagePrefix.isEmpty() ? "" : messagePrefix + " ";
    }

    /**
     * Performs the tr operation for the client messages.
     *
     * @param key the cryptographic key material for this operation
     * @param args the args supplied to this operation
     * @return the result described above
     */
    public static String tr(String key, Object... args) {
        return applyMessagePrefix(I18n.get(key, args));
    }

    /**
     * Returns the recorded message for the client messages.
     *
     * @param message the message supplied to this operation
     * @return the result described above
     */
    private static String applyMessagePrefix(String message) {
        if (message.startsWith(DEFAULT_MESSAGE_PREFIX)) {
            return (messagePrefix + message.substring(DEFAULT_MESSAGE_PREFIX.length())).stripLeading();
        }
        return message;
    }
}
