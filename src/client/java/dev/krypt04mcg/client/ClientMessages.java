package dev.krypt04mcg.client;

import net.minecraft.client.resources.language.I18n;

public final class ClientMessages {
    private ClientMessages() {
    }

    public static String tr(String key, Object... args) {
        return I18n.get(key, args);
    }
}
