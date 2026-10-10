package dev.krypt04mcg.config;

import com.terraformersmc.modmenu.api.ConfigScreenFactory;
import dev.krypt04mcg.Krypt04McgMod;
import net.fabricmc.loader.api.FabricLoader;

public final class OptionalClothConfigScreens {
    private static final String CLOTH_CONFIG_MOD_ID = "cloth-config";

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private OptionalClothConfigScreens() {
    }

    /**
     * Performs the config screen factory operation for the optional cloth config screens.
     *
     * @return the result described above
     */
    public static ConfigScreenFactory<?> configScreenFactory() {
        if (!FabricLoader.getInstance().isModLoaded(CLOTH_CONFIG_MOD_ID)) {
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
