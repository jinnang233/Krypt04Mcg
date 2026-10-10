package dev.krypt04mcg.config;

import com.terraformersmc.modmenu.api.ConfigScreenFactory;
import com.terraformersmc.modmenu.api.ModMenuApi;

public final class Krypt04McgModMenu implements ModMenuApi {
    /**
     * Returns the mod config screen factory exposed by the krypt04 mcg mod menu.
     *
     * @return the result described above
     */
    @Override
    public ConfigScreenFactory<?> getModConfigScreenFactory() {
        return OptionalClothConfigScreens.configScreenFactory();
    }
}
