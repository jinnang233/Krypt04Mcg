package dev.obscuralink.command;

import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import dev.obscuralink.chat.ChatSendService;
import dev.obscuralink.config.ObscuraLinkConfig;
import dev.obscuralink.model.GroupRecord;
import dev.obscuralink.model.PublicIdentity;
import dev.obscuralink.model.SessionRecord;
import dev.obscuralink.model.TrustState;
import dev.obscuralink.service.DecryptionHistoryService;
import dev.obscuralink.service.GroupService;
import dev.obscuralink.service.KeyStoreService;
import dev.obscuralink.service.KeyTrustService;
import dev.obscuralink.service.SessionService;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.text.Text;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public final class CommandRegistrar {
    private static final DateTimeFormatter STATUS_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private CommandRegistrar() {
    }

    public static void register(ChatSendService chatSendService, KeyStoreService keyStoreService,
                                KeyTrustService keyTrustService, SessionService sessionService,
                                DecryptionHistoryService decryptionHistoryService, GroupService groupService,
                                ObscuraLinkConfig config) {
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> {
            LiteralArgumentBuilder<FabricClientCommandSource> root = ClientCommandManager.literal("enc")
                    .then(tellCommand(chatSendService, false))
                    .then(tellCommand(chatSendService, true))
                    .then(exchangeCommand(chatSendService))
                    .then(etellCommand(chatSendService))
                    .then(gtellCommand(chatSendService, groupService))
                    .then(groupCommand(groupService))
                    .then(resendCommand(chatSendService))
                    .then(sessionCommand(chatSendService, sessionService, config))
                    .then(showAlgorithmsCommand(config))
                    .then(statusCommand(keyStoreService, keyTrustService, sessionService, decryptionHistoryService, config))
                    .then(keyCommand(keyStoreService, keyTrustService));
            dispatcher.register(root);
        });
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> tellCommand(ChatSendService chatSendService, boolean signed) {
        return ClientCommandManager.literal(signed ? "stell" : "tell")
                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                        .then(ClientCommandManager.argument("message", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    chatSendService.sendKemMessage(
                                            StringArgumentType.getString(ctx, "receiver"),
                                            StringArgumentType.getString(ctx, "message"),
                                            signed);
                                    return 1;
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> exchangeCommand(ChatSendService chatSendService) {
        return ClientCommandManager.literal("exchange")
                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                        .executes(ctx -> {
                            chatSendService.exchange(StringArgumentType.getString(ctx, "receiver"));
                            return 1;
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> etellCommand(ChatSendService chatSendService) {
        return ClientCommandManager.literal("etell")
                .then(ClientCommandManager.argument("receiver", StringArgumentType.word())
                        .then(ClientCommandManager.argument("message", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    chatSendService.sendSessionMessage(
                                            StringArgumentType.getString(ctx, "receiver"),
                                            StringArgumentType.getString(ctx, "message"));
                                    return 1;
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> gtellCommand(ChatSendService chatSendService,
                                                                                 GroupService groupService) {
        return ClientCommandManager.literal("gtell")
                .then(ClientCommandManager.argument("group", StringArgumentType.word())
                        .then(ClientCommandManager.argument("message", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    String group = StringArgumentType.getString(ctx, "group");
                                    try {
                                        GroupRecord record = groupService.find(group)
                                                .orElseThrow(() -> new IllegalStateException("No group named " + group));
                                        chatSendService.sendGroupMessage(record.name(), record.members(),
                                                StringArgumentType.getString(ctx, "message"));
                                        return 1;
                                    } catch (Exception e) {
                                        feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                        return 0;
                                    }
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> groupCommand(GroupService groupService) {
        return ClientCommandManager.literal("group")
                .then(ClientCommandManager.literal("create")
                        .then(ClientCommandManager.argument("name", StringArgumentType.word())
                                .then(ClientCommandManager.argument("members", StringArgumentType.greedyString())
                                        .executes(ctx -> {
                                            String name = StringArgumentType.getString(ctx, "name");
                                            List<String> members = parseMembers(StringArgumentType.getString(ctx, "members"));
                                            try {
                                                GroupRecord group = groupService.create(name, members);
                                                feedback(ctx.getSource(), "Created group " + group.name()
                                                        + " with " + group.members().size() + " members.");
                                                return 1;
                                            } catch (Exception e) {
                                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                                return 0;
                                            }
                                        }))))
                .then(ClientCommandManager.literal("list")
                        .executes(ctx -> {
                            try {
                                List<GroupRecord> groups = groupService.list();
                                if (groups.isEmpty()) {
                                    feedback(ctx.getSource(), "No groups.");
                                }
                                for (GroupRecord group : groups) {
                                    feedback(ctx.getSource(), group.name() + ": " + String.join(", ", group.members()));
                                }
                                return groups.size();
                            } catch (Exception e) {
                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                return 0;
                            }
                        }))
                .then(ClientCommandManager.literal("delete")
                        .then(ClientCommandManager.argument("name", StringArgumentType.word())
                                .executes(ctx -> {
                                    String name = StringArgumentType.getString(ctx, "name");
                                    try {
                                        groupService.delete(name);
                                        feedback(ctx.getSource(), "Deleted group " + name + ".");
                                        return 1;
                                    } catch (Exception e) {
                                        feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                        return 0;
                                    }
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> resendCommand(ChatSendService chatSendService) {
        return ClientCommandManager.literal("resend")
                .executes(ctx -> {
                    chatSendService.resendLatest();
                    return 1;
                })
                .then(ClientCommandManager.argument("messageId", StringArgumentType.word())
                        .executes(ctx -> {
                            chatSendService.resend(StringArgumentType.getString(ctx, "messageId"));
                            return 1;
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> sessionCommand(ChatSendService chatSendService,
                                                                                   SessionService sessionService,
                                                                                   ObscuraLinkConfig config) {
        return ClientCommandManager.literal("session")
                .then(ClientCommandManager.literal("list")
                        .executes(ctx -> {
                            try {
                                List<SessionRecord> sessions = sessionService.list();
                                if (sessions.isEmpty()) {
                                    feedback(ctx.getSource(), "No sessions.");
                                }
                                for (SessionRecord session : sessions) {
                                    String status = sessionService.isExpired(session, config.sessionTtlMinutes,
                                            config.maxMessagesPerSession, config.rotateAfterBytes) ? "expired" : "active";
                                    feedback(ctx.getSource(), session.peer() + " " + status
                                            + " messages=" + session.messageCount()
                                            + " bytes=" + session.bytesUsed());
                                }
                                return sessions.size();
                            } catch (Exception e) {
                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                return 0;
                            }
                        }))
                .then(ClientCommandManager.literal("clear")
                        .then(ClientCommandManager.argument("player", StringArgumentType.word())
                                .executes(ctx -> {
                                    String player = StringArgumentType.getString(ctx, "player");
                                    try {
                                        sessionService.clear(player);
                                        feedback(ctx.getSource(), "Cleared session for " + player + ".");
                                        return 1;
                                    } catch (Exception e) {
                                        feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                        return 0;
                                    }
                                })))
                .then(ClientCommandManager.literal("refresh")
                        .then(ClientCommandManager.argument("player", StringArgumentType.word())
                                .executes(ctx -> {
                                    chatSendService.exchange(StringArgumentType.getString(ctx, "player"));
                                    return 1;
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> showAlgorithmsCommand(ObscuraLinkConfig config) {
        return ClientCommandManager.literal("showalgs")
                .executes(ctx -> {
                    feedback(ctx.getSource(), "KEM=" + config.kemAlgorithm
                            + ", SIG=" + config.signatureAlgorithm
                            + ", AEAD=" + config.aeadAlgorithm);
                    return 1;
                });
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> statusCommand(KeyStoreService keyStoreService,
                                                                                  KeyTrustService keyTrustService,
                                                                                  SessionService sessionService,
                                                                                  DecryptionHistoryService decryptionHistoryService,
                                                                                  ObscuraLinkConfig config) {
        return ClientCommandManager.literal("status")
                .then(ClientCommandManager.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            showStatus(ctx.getSource(), StringArgumentType.getString(ctx, "player"),
                                    keyStoreService, keyTrustService, sessionService, decryptionHistoryService, config);
                            return 1;
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> keyCommand(KeyStoreService keyStoreService,
                                                                               KeyTrustService keyTrustService) {
        return ClientCommandManager.literal("key")
                .then(ClientCommandManager.literal("list")
                        .executes(ctx -> {
                            try {
                                List<PublicIdentity> identities = keyStoreService.listPublicIdentities();
                                if (identities.isEmpty()) {
                                    feedback(ctx.getSource(), "No imported public keys.");
                                }
                                for (PublicIdentity identity : identities) {
                                    feedback(ctx.getSource(), identity.owner() + " kem="
                                            + identity.kemPublicKey().fingerprint() + " sig="
                                            + identity.signaturePublicKey().fingerprint());
                                }
                                return identities.size();
                            } catch (Exception e) {
                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                return 0;
                            }
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
                                        return 1;
                                    } catch (Exception e) {
                                        feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                        return 0;
                                    }
                                })))
                .then(ClientCommandManager.literal("export")
                        .executes(ctx -> {
                            try {
                                feedback(ctx.getSource(), keyStoreService.exportOwnPublic());
                                return 1;
                            } catch (Exception e) {
                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                return 0;
                            }
                        }))
                .then(ClientCommandManager.literal("import")
                        .then(ClientCommandManager.argument("player", StringArgumentType.word())
                                .then(ClientCommandManager.argument("data_or_file", StringArgumentType.greedyString())
                                        .executes(ctx -> {
                                            String player = StringArgumentType.getString(ctx, "player");
                                            try {
                                                keyStoreService.importPublicIdentity(player,
                                                        StringArgumentType.getString(ctx, "data_or_file"));
                                                keyTrustService.markTofuTrusted(player);
                                                feedback(ctx.getSource(), "Imported public key for " + player + " with TOFU trust.");
                                                return 1;
                                            } catch (Exception e) {
                                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                                return 0;
                                            }
                                        }))))
                .then(trustCommand("confirm", keyStoreService, keyTrustService, TrustState.VERIFIED))
                .then(verifyCommand(keyStoreService, keyTrustService))
                .then(trustCommand("trust", keyStoreService, keyTrustService, TrustState.TOFU_TRUSTED))
                .then(trustCommand("distrust", keyStoreService, keyTrustService, TrustState.DISTRUSTED));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> trustCommand(String name, KeyStoreService keyStoreService,
                                                                                 KeyTrustService keyTrustService,
                                                                                 TrustState trustState) {
        return ClientCommandManager.literal(name)
                .then(ClientCommandManager.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            String player = StringArgumentType.getString(ctx, "player");
                            try {
                                keyStoreService.findPublicIdentity(player)
                                        .orElseThrow(() -> new IllegalStateException("No public key for " + player));
                                switch (trustState) {
                                    case VERIFIED -> {
                                        keyTrustService.markVerified(player);
                                        feedback(ctx.getSource(), "Confirmed fingerprint for " + player + ".");
                                    }
                                    case TOFU_TRUSTED -> {
                                        keyTrustService.markTofuTrusted(player);
                                        feedback(ctx.getSource(), "Marked " + player + " as TOFU trusted.");
                                    }
                                    case DISTRUSTED -> {
                                        keyTrustService.markDistrusted(player);
                                        feedback(ctx.getSource(), "Marked " + player + " as distrusted.");
                                    }
                                    default -> throw new IllegalStateException("Unsupported trust state: " + trustState);
                                }
                                return 1;
                            } catch (Exception e) {
                                feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                return 0;
                            }
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> verifyCommand(KeyStoreService keyStoreService,
                                                                                  KeyTrustService keyTrustService) {
        return ClientCommandManager.literal("verify")
                .then(ClientCommandManager.argument("player", StringArgumentType.word())
                        .then(ClientCommandManager.argument("fingerprint", StringArgumentType.word())
                                .executes(ctx -> {
                                    String player = StringArgumentType.getString(ctx, "player");
                                    String fingerprint = StringArgumentType.getString(ctx, "fingerprint");
                                    try {
                                        PublicIdentity identity = keyStoreService.findPublicIdentity(player)
                                                .orElseThrow(() -> new IllegalStateException("No public key for " + player));
                                        if (!keyTrustService.fingerprintMatches(identity, fingerprint)) {
                                            feedback(ctx.getSource(), "ERROR: fingerprint does not match " + player + ".");
                                            return 0;
                                        }
                                        keyTrustService.markVerified(player);
                                        feedback(ctx.getSource(), "Verified fingerprint for " + player + ".");
                                        return 1;
                                    } catch (Exception e) {
                                        feedback(ctx.getSource(), "ERROR: " + e.getMessage());
                                        return 0;
                                    }
                                })));
    }

    private static void showStatus(FabricClientCommandSource source, String player, KeyStoreService keyStoreService,
                                   KeyTrustService keyTrustService, SessionService sessionService,
                                   DecryptionHistoryService decryptionHistoryService, ObscuraLinkConfig config) {
        try {
            Optional<PublicIdentity> identity = keyStoreService.findPublicIdentity(player);
            Optional<SessionRecord> session = sessionService.find(player);
            TrustState trustState = keyTrustService.trustState(player, identity.isPresent());
            String keyStatus = identity.map(value -> "imported / " + trustState).orElse("not imported");
            String signatureStatus = identity.map(value -> value.signaturePublicKey() == null ? "unavailable" : "available")
                    .orElse("unavailable");
            String sessionStatus = session.map(value -> {
                boolean expired = sessionService.isExpired(value, config.sessionTtlMinutes,
                        config.maxMessagesPerSession, config.rotateAfterBytes);
                return (expired ? "expired, " : "established, ") + "sessionId=" + value.sessionId()
                        + " messages=" + value.messageCount() + " bytes=" + value.bytesUsed();
            }).orElse("not established");
            String lastDecrypt = decryptionHistoryService.lastSuccess(player)
                    .map(STATUS_TIME_FORMATTER::format)
                    .orElse("never");

            feedback(source, "Player: " + player);
            feedback(source, "Public key: " + keyStatus);
            identity.ifPresent(value -> feedback(source, "Fingerprint: kem=" + value.kemPublicKey().fingerprint()
                    + " sig=" + value.signaturePublicKey().fingerprint()));
            feedback(source, "Signature verification: " + signatureStatus);
            feedback(source, "Session: " + sessionStatus);
            feedback(source, "Last successful decrypt: " + lastDecrypt);
            feedback(source, "Algorithms: " + config.kemAlgorithm + " + " + config.signatureAlgorithm + " + " + config.aeadAlgorithm);
        } catch (Exception e) {
            feedback(source, "ERROR: " + e.getMessage());
        }
    }

    private static List<String> parseMembers(String raw) {
        return Pattern.compile("[,\\s]+")
                .splitAsStream(raw.trim())
                .filter(value -> !value.isBlank())
                .toList();
    }

    private static void feedback(FabricClientCommandSource source, String message) {
        source.sendFeedback(Text.literal("[ObscuraLink] " + message));
    }
}
