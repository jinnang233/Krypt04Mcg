package dev.krypt04mcg;

import dev.krypt04mcg.chat.ChatReceiveHandler;
import dev.krypt04mcg.chat.ChatConversationStore;
import dev.krypt04mcg.chat.ChatSendService;
import dev.krypt04mcg.chat.TransferProgressTracker;
import dev.krypt04mcg.client.TransferProgressHud;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.command.CommandRegistrar;
import dev.krypt04mcg.config.ChatSendMode;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.config.OptionalClothConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.gui.Krypt04McgChatScreen;
import dev.krypt04mcg.gui.Krypt04McgKeyManagerScreen;
import dev.krypt04mcg.input.Krypt04McgKeyBindings;
import dev.krypt04mcg.model.ChatSendFragment;
import dev.krypt04mcg.protocol.ClientboundChatFragmentPayload;
import dev.krypt04mcg.protocol.ChatFragmentPayload;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.protocol.ServerboundChatFragmentPayload;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.GroupService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SentMessageCacheService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.util.AccountStorage;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.message.v1.ClientReceiveMessageEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.Minecraft;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Krypt04McgMod implements ClientModInitializer {
    public static final String MOD_ID = "krypt04mcg";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);
    private static final String DISCLAIMER_KEY = "text.krypt04mcg.warning.disclaimer";

    private static Krypt04McgMod instance;

    private Krypt04McgConfig config;
    private KeyStoreService keyStoreService;
    private SessionService sessionService;
    private SessionHandshakeService sessionHandshakeService;
    private DecryptionHistoryService decryptionHistoryService;
    private GroupService groupService;
    private KeyTrustService keyTrustService;
    private SentMessageCacheService sentMessageCacheService;
    private FragmentService fragmentService;
    private ChatSendService chatSendService;
    private ChatReceiveHandler chatReceiveHandler;
    private ChatConversationStore conversationStore;
    private TransferProgressTracker transferProgress;
    private TransferProgressHud transferProgressHud;

    /**
     * Returns the recorded instance for the krypt04 mcg mod.
     *
     * @return the result described above
     */
    public static Krypt04McgMod instance() {
        return instance;
    }

    /**
     * Handles the initialize client callback for the krypt04 mcg mod.
     */
    @Override
    public void onInitializeClient() {
        instance = this;
        config = OptionalClothConfig.loadOrDefault();
        ClientMessages.setMessagePrefix(config.messagePrefix);
        transferProgress = new TransferProgressTracker();
        transferProgressHud = new TransferProgressHud(transferProgress, config);

        PacketCodec packetCodec = new PacketCodec();
        CryptoService cryptoService = new CryptoService();
        fragmentService = new FragmentService();
        FragmentReassembler reassembler = new FragmentReassembler();
        Minecraft client = Minecraft.getInstance();
        String owner = client.getUser().getName();
        String uuid = client.getUser().getProfileId() == null ? "" : client.getUser().getProfileId().toString();
        Path baseRoot = FabricLoader.getInstance().getConfigDir().resolve("krypt04mcg");
        Path root;
        try {
            root = AccountStorage.resolve(baseRoot, owner, uuid);
        } catch (Exception e) {
            LOGGER.error("Unable to initialize account-scoped Krypt04Mcg storage", e);
            system(ClientMessages.tr("text.krypt04mcg.error.key_init_failed"));
            return;
        }
        keyStoreService = new KeyStoreService(root, cryptoService);
        sessionService = new SessionService(root);
        sessionHandshakeService = new SessionHandshakeService(cryptoService, sessionService);
        decryptionHistoryService = new DecryptionHistoryService(root);
        groupService = new GroupService(root);
        keyTrustService = new KeyTrustService(root);
        sentMessageCacheService = new SentMessageCacheService(root);
        conversationStore = new ChatConversationStore(root, () -> config.enableConversationHistory);

        try {
            keyStoreService.init(owner, uuid, config.kemAlgorithm, config.signatureAlgorithm);
            sessionService.migrateLegacyFiles();
        } catch (Exception e) {
            LOGGER.error("Unable to initialize Krypt04Mcg keys", e);
            system(ClientMessages.tr("text.krypt04mcg.error.key_init_failed"));
            return;
        }

        chatSendService = new ChatSendService(config, keyStoreService, keyTrustService, sessionService,
                sessionHandshakeService, sentMessageCacheService, cryptoService, packetCodec,
                fragmentService, this::sendChatLine, this::system, client::getConnection);
        chatSendService.setProgressListener(transferProgress);
        chatSendService.setCustomPayloadTransport(this::sendCustomPayload,
                () -> client.getConnection() != null && ClientPlayNetworking.canSend(ServerboundChatFragmentPayload.TYPE));
        applyChatSender();
        ClientPlayConnectionEvents.DISCONNECT.register((handler, c) -> clearChatTransfers());
        OptionalClothConfig.registerSaveListener(updated -> {
            ClientMessages.setMessagePrefix(updated.messagePrefix);
            applyChatSender();
        });
        chatReceiveHandler = new ChatReceiveHandler(config, keyStoreService, keyTrustService, cryptoService,
                packetCodec, fragmentService, reassembler, decryptionHistoryService, sessionService,
                sessionHandshakeService, chatSendService::sendPacket, this::system, conversationStore::incoming);
        chatReceiveHandler.setProgressListener(transferProgress);
        net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents.END_CLIENT_TICK.register(c -> {
            chatSendService.tick();
            chatReceiveHandler.tick();
        });
        net.fabricmc.fabric.api.client.rendering.v1.hud.HudElementRegistry.attachElementAfter(
                net.fabricmc.fabric.api.client.rendering.v1.hud.VanillaHudElements.CHAT,
                net.minecraft.resources.Identifier.fromNamespaceAndPath(MOD_ID, "transfer_progress"),
                (graphics, delta) -> transferProgressHud.render(graphics));
        registerCustomPayloadNetworking();
        var optionalSharing = new dev.krypt04mcg.client.OptionalSharing(config, keyStoreService,
                keyTrustService, cryptoService, root);
        optionalSharing.register();
        var apiSessions = new SessionService(root.resolve("stream-api"));
        var apiHandshake = new SessionHandshakeService(cryptoService, apiSessions);
        var dataApi = new dev.krypt04mcg.service.DataTransferService(config, keyStoreService, keyTrustService, apiSessions, apiHandshake,
                () -> client.getConnection() != null && ClientPlayNetworking.canSend(dev.krypt04mcg.protocol.ControlPayload.TYPE),
                payload -> {
                    if (!ClientPlayNetworking.canSend(payload.type())) throw new IllegalStateException("Raw channel unavailable");
                    ClientPlayNetworking.send(payload);
                });
        dev.krypt04mcg.api.Krypt04McgApi.initialize(dataApi::send, dataApi::connect, dataApi::open);
        PayloadTypeRegistry.serverboundPlay().register(dev.krypt04mcg.protocol.ControlPayload.TYPE, dev.krypt04mcg.protocol.ControlPayload.CODEC);
        PayloadTypeRegistry.clientboundPlay().register(dev.krypt04mcg.protocol.ControlPayload.TYPE, dev.krypt04mcg.protocol.ControlPayload.CODEC);
        ClientPlayNetworking.registerGlobalReceiver(dev.krypt04mcg.protocol.ControlPayload.TYPE,
                (payload, context) -> context.client().execute(() -> dataApi.receive(payload)));
        for (var type : dev.krypt04mcg.protocol.RawChannelPayload.types(config.apiChannelCount)) {
            int slot = Integer.parseInt(type.id().getPath().substring("data/".length()));
            var codec = dev.krypt04mcg.protocol.RawChannelPayload.codec(slot);
            PayloadTypeRegistry.serverboundPlay().register(type, codec);
            PayloadTypeRegistry.clientboundPlay().register(type, codec);
            ClientPlayNetworking.registerGlobalReceiver(type,
                    (payload, context) -> context.client().execute(() -> dataApi.receive(payload)));
        }
        net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents.END_CLIENT_TICK.register(c -> dataApi.tick());
        ClientPlayConnectionEvents.DISCONNECT.register((handler, c) -> dataApi.clear());
        OptionalClothConfig.registerSaveListener(updated -> dataApi.tick());
        OptionalClothConfig.registerSaveListener(updated -> optionalSharing.applySettings());

        CommandRegistrar.register(chatSendService, keyStoreService, keyTrustService, sessionService, decryptionHistoryService,
                groupService, config);
        Krypt04McgKeyBindings.register(this);
        ClientReceiveMessageEvents.ALLOW_CHAT.register((message, signedMessage, sender, params, receptionTimestamp) -> {
            String senderName = sender == null ? null : sender.name();
            String raw = message.getString();
            if (!isLocalSender(senderName, owner)) {
                chatReceiveHandler.handle(senderName, raw);
            }
            return !chatReceiveHandler.shouldHide(raw);
        });
        ClientReceiveMessageEvents.ALLOW_GAME.register((message, overlay) -> {
            Optional<ShadowMessage> shadowMessage = extractShadowMessage(message.getString());
            shadowMessage
                    .filter(value -> !isLocalSender(value.player(), owner))
                    .ifPresent(value -> chatReceiveHandler.handle(null, value.message()));
            return shadowMessage.map(value -> !chatReceiveHandler.shouldHide(value.message())).orElse(true);
        });
        ClientPlayConnectionEvents.JOIN.register((handler, sender, joinedClient) -> {
            clearChatTransfers();
            showDisclaimer(joinedClient);
        });
        LOGGER.info("Krypt04Mcg initialized");
    }

    /**
     * Performs the open key manager screen operation for the krypt04 mcg mod.
     */
    public void openKeyManagerScreen() {
        Minecraft client = Minecraft.getInstance();
        if (chatSendService == null || keyStoreService == null) {
            return;
        }
        client.gui.setScreen(new Krypt04McgKeyManagerScreen(null, keyStoreService, keyTrustService,
                sessionService, config));
    }

    /**
     * Performs the open chat screen operation for the krypt04 mcg mod.
     */
    public void openChatScreen() {
        Minecraft client = Minecraft.getInstance();
        if (chatSendService == null || keyStoreService == null || client.player == null) {
            return;
        }
        client.gui.setScreen(new Krypt04McgChatScreen(chatSendService, keyStoreService, groupService, conversationStore));
    }

    /**
     * Submits chat line through the krypt04 mcg mod path. Local submission does not by itself acknowledge
     * remote receipt.
     *
     * @param chatSendFragment the chat send fragment supplied to this operation
     */
    private void sendChatLine(ChatSendFragment chatSendFragment) {
        Minecraft client = Minecraft.getInstance();
        String line = chatSendFragment.fragment();
        if (!fragmentService.isFragment(line, config.packetPrefix)) {
            throw new IllegalArgumentException("Invalid Krypt04Mcg chat fragment");
        }
        if (client.getConnection() == null) throw new IllegalStateException("Not connected to a server");
        client.getConnection().sendChat(line);
    }

    /**
     * Submits server command through the krypt04 mcg mod path. Local submission does not by itself
     * acknowledge remote receipt.
     *
     * @param chatSendFragment the chat send fragment supplied to this operation
     */
    private void sendServerCommand(ChatSendFragment chatSendFragment) {
        Minecraft client = Minecraft.getInstance();
        String fragment = chatSendFragment.fragment();
        if (!fragmentService.isFragment(fragment, config.packetPrefix)) {
            throw new IllegalArgumentException("Invalid Krypt04Mcg command fragment");
        }
        if (client.getConnection() == null) throw new IllegalStateException("Not connected to a server");
        client.getConnection().sendCommand(formatServerCommand(config.serverCommandTemplate, chatSendFragment));
    }

    /**
     * Performs the apply chat sender operation for the krypt04 mcg mod.
     */
    private void applyChatSender() {
        if (chatSendService == null) {
            return;
        }
        clearChatTransfers();
        if (config.chatSendMode == ChatSendMode.SERVER_COMMAND) {
            chatSendService.setChatSender(this::sendServerCommand);
        } else if (config.chatSendMode == ChatSendMode.CUSTOM_PAYLOAD) {
            chatSendService.setChatSender(this::sendCustomPayload);
        } else {
            chatSendService.setChatSender(this::sendChatLine);
        }
    }

    /**
     * Submits custom payload through the krypt04 mcg mod path. Local submission does not by itself
     * acknowledge remote receipt.
     *
     * @param chatSendFragment the chat send fragment supplied to this operation
     */
    private void sendCustomPayload(ChatSendFragment chatSendFragment) {
        String fragment = chatSendFragment.fragment();
        if (!fragmentService.isFragment(fragment, config.packetPrefix)) {
            throw new IllegalArgumentException("Invalid Krypt04Mcg payload fragment");
        }
        if (ClientPlayNetworking.canSend(ServerboundChatFragmentPayload.TYPE)) {
            ClientPlayNetworking.send(new ServerboundChatFragmentPayload(
                    chatSendFragment.receiver(), fragment, chatSendFragment.version()));
        } else {
            throw new IllegalStateException("Krypt04Mcg payload channel is not available on this server: " + ChatFragmentPayload.CHANNEL);
        }
    }

    /**
     * Performs the clear chat transfers operation for the krypt04 mcg mod.
     */
    private void clearChatTransfers() {
        chatSendService.clearPending();
        if (chatReceiveHandler != null) chatReceiveHandler.clearPending();
        transferProgress.clear();
    }

    /**
     * Draws transfer progress from the available client state.
     *
     * @param graphics the graphics supplied to this operation
     */
    public void renderTransferProgress(net.minecraft.client.gui.GuiGraphicsExtractor graphics) {
        if (transferProgressHud != null) transferProgressHud.render(graphics);
    }

    /**
     * Registers custom payload networking for the krypt04 mcg mod.
     */
    private void registerCustomPayloadNetworking() {
        PayloadTypeRegistry.serverboundPlay().register(
                ServerboundChatFragmentPayload.TYPE, ServerboundChatFragmentPayload.CODEC);
        PayloadTypeRegistry.clientboundPlay().register(
                ClientboundChatFragmentPayload.TYPE, ClientboundChatFragmentPayload.CODEC);
        ClientPlayNetworking.registerGlobalReceiver(ClientboundChatFragmentPayload.TYPE, (payload, context) -> {
            if (payload.sender().isBlank()) {
                LOGGER.warn("Ignoring Krypt04Mcg payload fragment without a server-authenticated sender");
                return;
            }
            chatReceiveHandler.handle(payload.sender(), payload.fragment());
        });
    }

    /**
     * Performs the format server command operation for the krypt04 mcg mod.
     *
     * @param template the template supplied to this operation
     * @param fragment the individual fragment or delivery record
     * @return the result described above
     */
    static String formatServerCommand(String template, ChatSendFragment fragment) {
        String command = template == null || template.isBlank() ? "/msg <receiver> <fragment>" : template;
        command = command.replace("<receiver>", fragment.receiver())
                .replace("<fragment>", fragment.fragment());
        return command.startsWith("/") ? command.substring(1) : command;
    }

    /**
     * Performs the system operation for the krypt04 mcg mod.
     *
     * @param message the message supplied to this operation
     */
    private void system(String message) {
        Minecraft client = Minecraft.getInstance();
        client.execute(() -> {
            if (client.gui != null) {
                client.gui.hud.getChat().addClientSystemMessage(Component.literal(message));
            }
        });
    }

    /**
     * Performs the show disclaimer operation for the krypt04 mcg mod.
     *
     * @param client the client supplied to this operation
     */
    private void showDisclaimer(Minecraft client) {
        if (!config.showDisclaimerWarning) {
            return;
        }
        LOGGER.debug(ClientMessages.tr(DISCLAIMER_KEY));
        client.execute(() -> {
            if (client.gui != null) {
                client.gui.hud.getChat().addClientSystemMessage(Component.empty()
                        .append(Component.literal(ClientMessages.messagePrefixWithSpace()).withStyle(ChatFormatting.RED, ChatFormatting.BOLD))
                        .append(Component.translatable(DISCLAIMER_KEY).withStyle(ChatFormatting.GOLD)));
            }
        });
    }

    /**
     * Performs the extract shadow message operation for the krypt04 mcg mod.
     *
     * @param raw the raw supplied to this operation
     * @return the result described above
     */
    private Optional<ShadowMessage> extractShadowMessage(String raw) {
        if (!config.shadowListenMode || raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        for (String regex : shadowListenRegexes()) {
            try {
                Matcher matcher = Pattern.compile(regex).matcher(raw);
                if (!matcher.matches()) {
                    continue;
                }
                String player = matcher.group("player");
                String message = matcher.group("message");
                if (player == null || message == null) {
                    continue;
                }
                return Optional.of(new ShadowMessage(player, message));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Invalid Krypt04Mcg shadow listen regex: {}", regex, e);
            }
        }
        return Optional.empty();
    }

    /**
     * Performs the shadow listen regexes operation for the krypt04 mcg mod.
     *
     * @return the result described above
     */
    private List<String> shadowListenRegexes() {
        if (config.shadowListenRegexes != null && !config.shadowListenRegexes.isEmpty()) {
            return config.shadowListenRegexes;
        }
        return List.of(config.shadowListenRegex);
    }

    /**
     * Reports whether local sender holds for the krypt04 mcg mod.
     *
     * @param senderName the sender name supplied to this operation
     * @param localName the local name supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean isLocalSender(String senderName, String localName) {
        return senderName != null && localName != null && senderName.equalsIgnoreCase(localName);
    }

    private record ShadowMessage(String player, String message) {
    }
}
