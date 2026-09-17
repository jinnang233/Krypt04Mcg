package dev.krypt04mcg.config;

import java.util.function.UnaryOperator;
import net.minecraft.client.gui.screens.Screen;
import me.shedaniel.autoconfig.AutoConfigClient;

public final class ClothConfigScreenBridge {
    private ClothConfigScreenBridge() {
    }

    public static UnaryOperator<Screen> configScreenFactory() {
        ClothConfigBridge.load();
        return parent -> AutoConfigClient.getConfigScreen(ClothKrypt04McgConfig.class, parent).get();
    }
}

