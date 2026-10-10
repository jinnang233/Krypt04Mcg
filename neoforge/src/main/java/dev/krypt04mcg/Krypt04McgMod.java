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
import dev.krypt04mcg.client.NeoChatPayload;
import dev.krypt04mcg.protocol.ChatFragmentPayload;
import dev.krypt04mcg.protocol.PacketCodec;

import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.GroupService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SentMessageCacheService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.util.AccountStorage;
import net.neoforged.fml.common.Mod;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.client.event.ClientChatReceivedEvent;
import net.neoforged.neoforge.client.event.ClientPlayerNetworkEvent;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import net.neoforged.neoforge.client.network.ClientPacketDistributor;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.client.network.event.RegisterClientPayloadHandlersEvent;
import net.neoforged.neoforge.network.registration.NetworkRegistry;
import net.neoforged.neoforge.client.gui.IConfigScreenFactory;





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

@Mod(value = Krypt04McgMod.MOD_ID, dist = Dist.CLIENT)
public final class Krypt04McgMod {
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
    private dev.krypt04mcg.service.DataTransferService dataApi;

    /**
     * Returns the recorded instance for the krypt04 mcg mod.
     *
     * @return the result described above
     */
    public static Krypt04McgMod instance() {
        return instance;
    }

    /**
     * Creates a krypt04 mcg mod with the supplied dependencies and initial state.
     *
     * @param modBus the mod bus supplied to this operation
     * @param container the container supplied to this operation
     */
    public Krypt04McgMod(IEventBus modBus, ModContainer container) {
        instance = this;
        modBus.addListener(this::registerPayloads);
        modBus.addListener(this::registerClientPayloads);
        modBus.addListener((net.neoforged.neoforge.client.event.RegisterGuiLayersEvent event) ->
                event.registerAboveAll(net.minecraft.resources.Identifier.fromNamespaceAndPath(MOD_ID, "transfer_progress"),
                        (graphics, delta) -> renderTransferProgress(graphics)));
        container.registerExtensionPoint(IConfigScreenFactory.class, (mc, parent) ->
                dev.krypt04mcg.config.OptionalClothConfigScreens.configScreenFactory().apply(parent));
        Krypt04McgKeyBindings.register(this, modBus);
        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> {
            if (config == null) onInitializeClient();
        });
    }

    /**
     * Handles the initialize client callback for the krypt04 mcg mod.
     */
    private void onInitializeClient() {
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
        Path baseRoot = client.gameDirectory.toPath().resolve("config").resolve("krypt04mcg");
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
        chatSendService.setCustomPayloadTransport(this::sendCustomPayload, () -> canSend(NeoChatPayload.TYPE));
        applyChatSender();
        NeoForge.EVENT_BUS.addListener((ClientPlayerNetworkEvent.LoggingOut event) -> clearChatTransfers());
        OptionalClothConfig.registerSaveListener(updated -> {
            ClientMessages.setMessagePrefix(updated.messagePrefix);
            applyChatSender();
        });
        chatReceiveHandler = new ChatReceiveHandler(config, keyStoreService, keyTrustService, cryptoService,
                packetCodec, fragmentService, reassembler, decryptionHistoryService, sessionService,
                sessionHandshakeService, chatSendService::sendPacket, this::system, conversationStore::incoming);
        chatReceiveHandler.setProgressListener(transferProgress);
        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> {
            chatSendService.tick();
            chatReceiveHandler.tick();
        });
        var optionalSharing = new dev.krypt04mcg.client.OptionalSharing(config, keyStoreService,
                keyTrustService, cryptoService, root);
        optionalSharing.register();
        var apiSessions = new SessionService(root.resolve("stream-api"));
        var apiHandshake = new SessionHandshakeService(cryptoService, apiSessions);
        dataApi = new dev.krypt04mcg.service.DataTransferService(config, keyStoreService, keyTrustService, apiSessions, apiHandshake,
                () -> canSend(dev.krypt04mcg.protocol.ControlPayload.TYPE), payload -> {
                    if (!canSend(payload.type())) throw new IllegalStateException("Raw channel unavailable");
                    ClientPacketDistributor.sendToServer(payload);
                });
        dev.krypt04mcg.api.Krypt04McgApi.initialize(dataApi::send, dataApi::connect, dataApi::open);
        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> dataApi.tick());
        NeoForge.EVENT_BUS.addListener((ClientPlayerNetworkEvent.LoggingOut event) -> dataApi.clear());
        OptionalClothConfig.registerSaveListener(updated -> dataApi.tick());
        OptionalClothConfig.registerSaveListener(updated -> optionalSharing.applySettings());

        CommandRegistrar.register(chatSendService, keyStoreService, keyTrustService, sessionService, decryptionHistoryService,
                groupService, config);
        NeoForge.EVENT_BUS.addListener((ClientChatReceivedEvent.Player event) -> {
            String raw = event.getMessage().getString();
            String senderName = null;
            var connection = Minecraft.getInstance().getConnection();
            if (connection != null && connection.getPlayerInfo(event.getSender()) != null)
                senderName = connection.getPlayerInfo(event.getSender()).getProfile().name();
            if (!isLocalSender(senderName, owner)) chatReceiveHandler.handle(senderName, raw);
            if (chatReceiveHandler.shouldHide(raw)) event.setCanceled(true);
        });
        NeoForge.EVENT_BUS.addListener((ClientChatReceivedEvent.System event) -> {
            var message = event.getMessage();
            Optional<ShadowMessage> shadowMessage = extractShadowMessage(message.getString());
            shadowMessage
                    .filter(value -> !isLocalSender(value.player(), owner))
                    .ifPresent(value -> chatReceiveHandler.handle(null, value.message()));
            if (shadowMessage.map(value -> chatReceiveHandler.shouldHide(value.message())).orElse(false)) event.setCanceled(true);
        });
        NeoForge.EVENT_BUS.addListener((ClientPlayerNetworkEvent.LoggingIn event) -> {
            clearChatTransfers();
            showDisclaimer(Minecraft.getInstance());
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
        if (canSend(NeoChatPayload.TYPE)) {
            ClientPacketDistributor.sendToServer(new NeoChatPayload(
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
     * Registers payloads for the krypt04 mcg mod.
     *
     * @param event the event supplied to this operation
     */
    private void registerPayloads(RegisterPayloadHandlersEvent event) {
        var registrar = event.registrar("1").optional();
        registrar.playBidirectional(NeoChatPayload.TYPE, NeoChatPayload.CODEC, (payload, context) -> {});
        registrar.playBidirectional(dev.krypt04mcg.protocol.ControlPayload.TYPE, dev.krypt04mcg.protocol.ControlPayload.CODEC, (payload, context) -> {});
        for (var type : dev.krypt04mcg.protocol.RawChannelPayload.types(OptionalClothConfig.loadOrDefault().apiChannelCount)) {
            int slot = Integer.parseInt(type.id().getPath().substring("data/".length()));
            registrar.playBidirectional(type, dev.krypt04mcg.protocol.RawChannelPayload.codec(slot), (payload, context) -> {});
        }
        dev.krypt04mcg.client.OptionalSharing.registerPayloads(registrar);
    }

    /**
     * Registers client payloads for the krypt04 mcg mod.
     *
     * @param event the event supplied to this operation
     */
    private void registerClientPayloads(RegisterClientPayloadHandlersEvent event) {
        event.register(NeoChatPayload.TYPE, (payload, context) -> {
            if (chatReceiveHandler == null) return;
            if (payload.peer().isBlank()) {
                LOGGER.warn("Ignoring Krypt04Mcg payload fragment without a server-authenticated sender");
                return;
            }
            chatReceiveHandler.handle(payload.peer(), payload.fragment());
        });
        event.register(dev.krypt04mcg.protocol.ControlPayload.TYPE, (payload, context) ->
                context.enqueueWork(() -> { if (dataApi != null) dataApi.receive(payload); }));
        for (var type : dev.krypt04mcg.protocol.RawChannelPayload.types(OptionalClothConfig.loadOrDefault().apiChannelCount)) {
            event.register(type, (payload, context) ->
                    context.enqueueWork(() -> { if (dataApi != null) dataApi.receive(payload); }));
        }
        dev.krypt04mcg.client.OptionalSharing.registerClientPayloads(event);
    }

    /**
     * Performs the can send operation for the krypt04 mcg mod.
     *
     * @param type the type supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean canSend(net.minecraft.network.protocol.common.custom.CustomPacketPayload.Type<?> type) {
        var connection = Minecraft.getInstance().getConnection();
        return connection != null && NetworkRegistry.hasChannel(connection, type.id());
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



