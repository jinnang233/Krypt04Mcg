package dev.krypt04mcg.input;

import com.mojang.blaze3d.platform.InputConstants;
import dev.krypt04mcg.Krypt04McgMod;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import net.neoforged.neoforge.client.event.RegisterKeyMappingsEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.bus.api.IEventBus;

import net.minecraft.client.KeyMapping;
import net.minecraft.resources.Identifier;
import org.lwjgl.glfw.GLFW;

public final class Krypt04McgKeyBindings {
    private static final KeyMapping.Category CATEGORY = KeyMapping.Category.register(
            Identifier.fromNamespaceAndPath(Krypt04McgMod.MOD_ID, "krypt04mcg")
    );
    private static KeyMapping openChatGui;

    private Krypt04McgKeyBindings() {
    }

    public static void register(Krypt04McgMod mod, IEventBus modBus) {
        openChatGui = new KeyMapping(
                "key.krypt04mcg.open_chat_gui",
                InputConstants.Type.KEYSYM,
                GLFW.GLFW_KEY_K,
                CATEGORY
        );
        modBus.addListener((RegisterKeyMappingsEvent event) -> {
            event.registerCategory(CATEGORY);
            event.register(openChatGui);
        });

        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> {
            while (openChatGui.consumeClick()) {
                mod.openChatScreen();
            }
        });
    }
}

