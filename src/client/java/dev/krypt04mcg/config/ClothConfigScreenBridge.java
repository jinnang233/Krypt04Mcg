package dev.krypt04mcg.config;

import com.terraformersmc.modmenu.api.ConfigScreenFactory;
import me.shedaniel.autoconfig.AutoConfigClient;

public final class ClothConfigScreenBridge {
    private ClothConfigScreenBridge() {
    }

    public static ConfigScreenFactory<?> configScreenFactory() {
        ClothConfigBridge.load();
        return parent -> AutoConfigClient.getConfigScreen(ClothKrypt04McgConfig.class, parent).get();
    }
}
