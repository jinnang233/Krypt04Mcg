package dev.krypt04mcg.config;

import java.util.function.UnaryOperator;
import net.minecraft.client.gui.screens.Screen;
import dev.krypt04mcg.Krypt04McgMod;
import net.neoforged.fml.ModList;

public final class OptionalClothConfigScreens {
    private static final String CLOTH_CONFIG_MOD_ID = "cloth-config";

    private OptionalClothConfigScreens() {
    }

    public static UnaryOperator<Screen> configScreenFactory() {
        if (!ModList.get().isLoaded(CLOTH_CONFIG_MOD_ID)) {
            return parent -> null;
        }
        try {
            return ClothConfigScreenBridge.configScreenFactory();
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to create Krypt04Mcg Cloth Config screen", e);
        }
        return parent -> null;
    }
}

