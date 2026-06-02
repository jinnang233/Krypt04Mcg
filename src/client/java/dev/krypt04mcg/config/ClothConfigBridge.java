package dev.krypt04mcg.config;

import me.shedaniel.autoconfig.AutoConfig;
import me.shedaniel.autoconfig.ConfigHolder;
import me.shedaniel.autoconfig.serializer.GsonConfigSerializer;
import net.minecraft.world.InteractionResult;

public final class ClothConfigBridge {
    private static boolean registered;
    private static Krypt04McgConfig runtimeConfig;

    private ClothConfigBridge() {
    }

    public static Krypt04McgConfig load() {
        register();
        ConfigHolder<ClothKrypt04McgConfig> holder = AutoConfig.getConfigHolder(ClothKrypt04McgConfig.class);
        if (runtimeConfig == null) {
            runtimeConfig = holder.getConfig().toCoreConfig();
        } else {
            holder.getConfig().copyTo(runtimeConfig);
        }
        return runtimeConfig;
    }

    private static void register() {
        if (registered) {
            return;
        }
        AutoConfig.register(ClothKrypt04McgConfig.class, GsonConfigSerializer::new);
        AutoConfig.getConfigHolder(ClothKrypt04McgConfig.class).registerSaveListener((holder, config) -> {
            if (runtimeConfig != null) {
                config.copyTo(runtimeConfig);
            }
            return InteractionResult.SUCCESS;
        });
        registered = true;
    }
}
