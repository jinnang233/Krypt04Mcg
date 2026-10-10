package dev.krypt04mcg.input;

import com.mojang.blaze3d.platform.InputConstants;
import dev.krypt04mcg.Krypt04McgMod;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import net.neoforged.neoforge.client.event.RegisterKeyMappingsEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.bus.api.IEventBus;

import net.minecraft.client.KeyMapping;
import net.minecraft.resources.Identifier;

public final class Krypt04McgKeyBindings {
    private static final KeyMapping.Category CATEGORY = KeyMapping.Category.register(
            Identifier.fromNamespaceAndPath(Krypt04McgMod.MOD_ID, "krypt04mcg")
    );
    private static KeyMapping openChatGui;
    private static KeyMapping openKeyManager;

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private Krypt04McgKeyBindings() {
    }

    /**
     * Registers the supported callbacks and channels for the krypt04 mcg key bindings.
     *
     * @param mod the mod supplied to this operation
     * @param modBus the mod bus supplied to this operation
     */
    public static void register(Krypt04McgMod mod, IEventBus modBus) {
        openChatGui = new KeyMapping(
                "key.krypt04mcg.open_chat_gui",
                InputConstants.Type.KEYBOARD,
                InputConstants.KEY_K,
                CATEGORY
        );
        openKeyManager = new KeyMapping(
                "key.krypt04mcg.open_key_manager",
                InputConstants.Type.KEYBOARD,
                InputConstants.UNKNOWN.getValue(),
                CATEGORY
        );
        modBus.addListener((RegisterKeyMappingsEvent event) -> {
            event.registerCategory(CATEGORY);
            event.register(openChatGui);
            event.register(openKeyManager);
        });

        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> {
            while (openKeyManager.consumeClick()) {
                mod.openKeyManagerScreen();
            }
            while (openChatGui.consumeClick()) {
                mod.openChatScreen();
            }
        });
    }
}

