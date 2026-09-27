package dev.krypt04mcg.config;

import dev.krypt04mcg.Krypt04McgMod;
import net.neoforged.fml.ModList;

import java.util.function.Consumer;

public final class OptionalClothConfig {
    // NeoForge uses an underscore; "cloth-config" is the Fabric mod ID.
    static final String CLOTH_CONFIG_MOD_ID = "cloth_config";

    private OptionalClothConfig() {
    }

    public static Krypt04McgConfig loadOrDefault() {
        if (!ModList.get().isLoaded(CLOTH_CONFIG_MOD_ID)) {
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
            return ConfigFileStore.load(net.neoforged.fml.loading.FMLPaths.CONFIGDIR.get().resolve("krypt04mcg.json"));
        } catch (java.io.IOException e) {
            Krypt04McgMod.LOGGER.warn("Unable to read Krypt04Mcg JSON settings; using defaults", e);
            return new Krypt04McgConfig();
        }
    }

    public static void registerSaveListener(Consumer<Krypt04McgConfig> listener) {
        if (!ModList.get().isLoaded(CLOTH_CONFIG_MOD_ID)) {
            return;
        }
        try {
            ClothConfigBridge.registerSaveListener(listener);
        } catch (LinkageError e) {
            Krypt04McgMod.LOGGER.warn("Unable to register Krypt04Mcg Cloth Config save listener", e);
        }
    }
}

