package dev.krypt04mcg.config;

import dev.krypt04mcg.Krypt04McgMod;
import net.fabricmc.loader.api.FabricLoader;

import java.util.function.Consumer;

public final class OptionalClothConfig {
    private static final String CLOTH_CONFIG_MOD_ID = "cloth-config";

    private OptionalClothConfig() {
    }

    public static Krypt04McgConfig loadOrDefault() {
        if (!FabricLoader.getInstance().isModLoaded(CLOTH_CONFIG_MOD_ID)) {
            return loadFile();
        }
        try {
            return ClothConfigBridge.load();
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to load Krypt04Mcg settings from Cloth Config; using JSON settings", e);
        }
        return loadFile();
    }

    private static Krypt04McgConfig loadFile() {
        try {
            return ConfigFileStore.load(FabricLoader.getInstance().getConfigDir().resolve("krypt04mcg.json"));
        } catch (java.io.IOException e) {
            Krypt04McgMod.LOGGER.warn("Unable to read Krypt04Mcg JSON settings; using defaults", e);
            return new Krypt04McgConfig();
        }
    }

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
