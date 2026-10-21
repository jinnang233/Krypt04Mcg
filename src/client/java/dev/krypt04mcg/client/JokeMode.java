package dev.krypt04mcg.client;

import dev.krypt04mcg.config.Krypt04McgConfig;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.resources.language.I18n;
import net.minecraft.network.chat.Component;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Gate for the joke build. While {@code jokeMode} is enabled, every player-initiated feature is
 * suspended and each attempt is answered with a randomly picked parental-complaint notice.
 *
 * <p>The joke is on purpose: this build is published with the {@code joke} release type and is
 * never announced as an update.</p>
 */
public final class JokeMode {
    private static final List<String> BLOCKED_KEYS = List.of(
            "text.krypt04mcg.joke.blocked.1",
            "text.krypt04mcg.joke.blocked.2",
            "text.krypt04mcg.joke.blocked.3",
            "text.krypt04mcg.joke.blocked.4",
            "text.krypt04mcg.joke.blocked.5",
            "text.krypt04mcg.joke.blocked.6"
    );
    private static final String JOIN_KEY = "text.krypt04mcg.joke.join";
    private static final String JOIN_HINT_KEY = "text.krypt04mcg.joke.join.hint";
    private static final String JOIN_CONFIG_KEY = "text.krypt04mcg.joke.join.config";

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private JokeMode() {
    }

    /**
     * Reports whether the joke switch is enabled for the supplied configuration.
     *
     * @param config the active configuration, possibly {@code null} during startup
     * @return whether every player-initiated feature must be suspended
     */
    public static boolean active(Krypt04McgConfig config) {
        return config != null && config.jokeMode;
    }

    /**
     * Returns a prefixed notice for chat lines that do not add the message prefix themselves.
     *
     * @return the configured prefix followed by a random complaint notice
     */
    public static String message() {
        return ClientMessages.messagePrefixWithSpace() + I18n.get(randomBlockedKey());
    }

    /**
     * Returns the notice without a prefix, for callers that prepend the configured prefix.
     *
     * @return a random complaint notice
     */
    public static String plainMessage() {
        return I18n.get(randomBlockedKey());
    }

    /**
     * Clearly announces the joke build whenever the player joins a world.
     *
     * @param client the client whose chat HUD receives the notice
     * @param version the installed mod version
     * @param jokeModeEnabled whether the feature suspension is currently active
     */
    public static void showJoinNotice(Minecraft client, String version, boolean jokeModeEnabled) {
        if (client == null) {
            return;
        }
        client.execute(() -> {
            if (client.gui == null) {
                return;
            }
            client.gui.hud.getChat().addClientSystemMessage(Component.empty()
                    .append(Component.literal(ClientMessages.messagePrefixWithSpace())
                            .withStyle(ChatFormatting.RED, ChatFormatting.BOLD))
                    .append(Component.translatable(JOIN_KEY, version).withStyle(ChatFormatting.GOLD)));
            client.gui.hud.getChat().addClientSystemMessage(Component.empty()
                    .append(Component.literal(ClientMessages.messagePrefixWithSpace())
                            .withStyle(ChatFormatting.RED, ChatFormatting.BOLD))
                    .append(Component.translatable(JOIN_HINT_KEY).withStyle(ChatFormatting.YELLOW)));
            if (jokeModeEnabled) {
                client.gui.hud.getChat().addClientSystemMessage(Component.empty()
                        .append(Component.literal(ClientMessages.messagePrefixWithSpace())
                                .withStyle(ChatFormatting.RED, ChatFormatting.BOLD))
                        .append(Component.translatable(JOIN_CONFIG_KEY).withStyle(ChatFormatting.GRAY)));
            }
        });
    }

    /**
     * Picks one of the complaint notices at random.
     *
     * @return the translation key of the selected notice
     */
    private static String randomBlockedKey() {
        return BLOCKED_KEYS.get(ThreadLocalRandom.current().nextInt(BLOCKED_KEYS.size()));
    }
}
