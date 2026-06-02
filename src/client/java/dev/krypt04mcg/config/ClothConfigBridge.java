package dev.krypt04mcg.config;

import me.shedaniel.autoconfig.AutoConfig;
import me.shedaniel.autoconfig.serializer.GsonConfigSerializer;

public final class ClothConfigBridge {
    private static boolean registered;

    private ClothConfigBridge() {
    }

    public static Krypt04McgConfig load() {
        register();
        return AutoConfig.getConfigHolder(ClothKrypt04McgConfig.class).getConfig();
    }

    private static void register() {
        if (registered) {
            return;
        }
        AutoConfig.register(ClothKrypt04McgConfig.class, GsonConfigSerializer::new);
        registered = true;
    }
}
