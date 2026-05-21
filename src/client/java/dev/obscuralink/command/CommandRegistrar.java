package dev.obscuralink.command;

import com.mojang.brigadier.arguments.StringArgumentType;
import dev.obscuralink.chat.ChatSendService;
import dev.obscuralink.config.ObscuraLinkConfig;
import dev.obscuralink.model.PublicIdentity;
import dev.obscuralink.service.KeyStoreService;
import dev.obscuralink.service.SessionService;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.text.Text;

import java.util.List;

public final class CommandRegistrar {
    private CommandRegistrar() {
    }

    public static void register(ChatSendService chatSendService, KeyStoreService keyStoreService,
                                SessionService sessionService, ObscuraLinkConfig config) {
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> dispatcher.register(
                ClientCommandManager.literal("enc")
                        .then(ClientCommandManager.literal("tell")
                                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                                        .then(ClientCommandManager.argument("message", StringArgumentType.greedyString())
                                                .executes(ctx -> {
                                                    chatSendService.sendKemMessage(
                                                            StringArgumentType.getString(ctx, "receiver"),
                                                            StringArgumentType.getString(ctx, "message"),
                                                            false);
                                                    return 1;
                                                }))))
                        .then(ClientCommandManager.literal("stell")
                                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                                        .then(ClientCommandManager.argument("message", StringArgumentType.greedyString())
                                                .executes(ctx -> {
                                                    chatSendService.sendKemMessage(
                                                            StringArgumentType.getString(ctx, "receiver"),
                                                            StringArgumentType.getString(ctx, "message"),
                                                            true);
                                                    return 1;
                                                }))))
                        .then(ClientCommandManager.literal("exchange")
                                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                                        .executes(ctx -> {
                                            chatSendService.exchange(StringArgumentType.getString(ctx, "receiver"));
                                            return 1;
                                        })))
                        .then(ClientCommandManager.literal("etell")
                                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                                        .then(ClientCommandManager.argument("message", StringArgumentType.greedyString())
                                                .executes(ctx -> {
                                                    chatSendService.sendSessionMessage(
                                                            StringArgumentType.getString(ctx, "receiver"),
                                                            StringArgumentType.getString(ctx, "message"));
                                                    return 1;
                                                }))))
                        .then(ClientCommandManager.literal("showalgs")
                                .executes(ctx -> {
                                    feedback(ctx.getSource(), "KEM=" + config.kemAlgorithm
                                            + ", SIG=" + config.signatureAlgorithm
                                            + ", AEAD=" + config.aeadAlgorithm);
                                    return 1;
                                }))
                                .then(ClientCommandManager.literal("key")
                                        .then(ClientCommandManager.literal("list")
                                        .executes(ctx -> {
                                            List<PublicIdentity> identities;
                                            try {
                                                identities = keyStoreService.listPublicIdentities();
                                            } catch (Exception e) {
                                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                                return 0;
                                            }
                                            if (identities.isEmpty()) {
                                                feedback(ctx.getSource(), "No imported public keys.");
                                            }
                                            for (PublicIdentity identity : identities) {
                                                feedback(ctx.getSource(), identity.owner() + " kem="
                                                        + identity.kemPublicKey().fingerprint() + " sig="
                                                        + identity.signaturePublicKey().fingerprint());
                                            }
                                            return identities.size();
                                        }))
                                .then(ClientCommandManager.literal("fingerprint")
                                        .then(ClientCommandManager.argument("player", StringArgumentType.word())
                                                .executes(ctx -> {
                                                    String player = StringArgumentType.getString(ctx, "player");
                                                    try {
                                                        PublicIdentity identity = keyStoreService.findPublicIdentity(player)
                                                                .orElseThrow(() -> new IllegalStateException("No public key for " + player));
                                                        feedback(ctx.getSource(), player + " kem="
                                                                + identity.kemPublicKey().fingerprint() + " sig="
                                                                + identity.signaturePublicKey().fingerprint());
                                                    } catch (Exception e) {
                                                        feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                                        return 0;
                                                    }
                                                    return 1;
                                                })))
                                .then(ClientCommandManager.literal("export")
                                        .executes(ctx -> {
                                            try {
                                                feedback(ctx.getSource(), keyStoreService.exportOwnPublic());
                                            } catch (Exception e) {
                                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                                return 0;
                                            }
                                            return 1;
                                        }))
                                .then(ClientCommandManager.literal("import")
                                        .then(ClientCommandManager.argument("player", StringArgumentType.word())
                                                .then(ClientCommandManager.argument("data_or_file", StringArgumentType.greedyString())
                                                        .executes(ctx -> {
                                                            String player = StringArgumentType.getString(ctx, "player");
                                                            try {
                                                                keyStoreService.importPublicIdentity(player,
                                                                        StringArgumentType.getString(ctx, "data_or_file"));
                                                                feedback(ctx.getSource(), "Imported public key for " + player + " with TOFU trust.");
                                                            } catch (Exception e) {
                                                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                                                return 0;
                                                            }
                                                            return 1;
                                                        })))))
        ));
    }

    private static void feedback(FabricClientCommandSource source, String message) {
        source.sendFeedback(Text.literal("[ObscuraLink] " + message));
    }
}
