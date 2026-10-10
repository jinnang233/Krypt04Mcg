package dev.krypt04mcg.config;

import java.util.function.UnaryOperator;
import net.minecraft.client.gui.screens.Screen;
import me.shedaniel.autoconfig.AutoConfigClient;

public final class ClothConfigScreenBridge {
    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private ClothConfigScreenBridge() {
    }

    /**
     * Performs the config screen factory operation for the cloth config screen bridge.
     *
     * @return the result described above
     */
    public static UnaryOperator<Screen> configScreenFactory() {
        ClothConfigBridge.load();
        return parent -> AutoConfigClient.getConfigScreen(ClothKrypt04McgConfig.class, parent).get();
    }
}

