package dev.krypt04mcg.config;

import dev.krypt04mcg.Krypt04McgMod;
import net.fabricmc.loader.api.FabricLoader;

import java.util.function.Consumer;

public final class OptionalClothConfig {
    private static final String CLOTH_CONFIG_MOD_ID = "cloth-config";

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private OptionalClothConfig() {
    }

    /**
     * Performs the load or default operation for the optional cloth config.
     *
     * @return the result described above
     */
    public static Krypt04McgConfig loadOrDefault() {
        if (!FabricLoader.getInstance().isModLoaded(CLOTH_CONFIG_MOD_ID)) {
            Krypt04McgMod.LOGGER.info("Cloth Config is not installed; using default Krypt04Mcg settings");
            return defaults();
        }
        try {
            return ClothConfigBridge.load();
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to load Krypt04Mcg settings from Cloth Config; using defaults", e);
        }
        return defaults();
    }

    /**
     * Returns the recorded config for the optional cloth config.
     *
     * @return the result described above
     */
    private static Krypt04McgConfig defaults() {
        var config = new Krypt04McgConfig();
        config.apiChannelCount = dev.krypt04mcg.channel.ChannelPoolConfig.load(FabricLoader.getInstance().getConfigDir());
        return config;
    }

    /**
     * Registers save listener for the optional cloth config.
     *
     * @param listener the listener supplied to this operation
     */
    public static void registerSaveListener(Consumer<Krypt04McgConfig> listener) {
        if (!FabricLoader.getInstance().isModLoaded(CLOTH_CONFIG_MOD_ID)) {
            return;
        }
        try {
            ClothConfigBridge.registerSaveListener(listener);
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to register Krypt04Mcg Cloth Config save listener", e);
        }
    }
}
