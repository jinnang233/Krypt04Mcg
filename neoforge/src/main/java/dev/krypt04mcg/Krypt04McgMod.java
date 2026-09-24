package dev.krypt04mcg;

import dev.krypt04mcg.chat.ChatReceiveHandler;
import dev.krypt04mcg.chat.ChatConversationStore;
import dev.krypt04mcg.chat.ChatSendService;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.command.CommandRegistrar;
import dev.krypt04mcg.config.ChatSendMode;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.config.OptionalClothConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.gui.Krypt04McgChatScreen;
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
    private dev.krypt04mcg.service.DataTransferService dataApi;

    public static Krypt04McgMod instance() {
        return instance;
    }

    public Krypt04McgMod(IEventBus modBus, ModContainer container) {
        instance = this;
        modBus.addListener(this::registerPayloads);
        modBus.addListener(this::registerClientPayloads);
        container.registerExtensionPoint(IConfigScreenFactory.class, (mc, parent) ->
                dev.krypt04mcg.config.OptionalClothConfigScreens.configScreenFactory().apply(parent));
        Krypt04McgKeyBindings.register(this, modBus);
        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> {
            if (config == null) onInitializeClient();
        });
    }

    private void onInitializeClient() {
        instance = this;
        config = OptionalClothConfig.loadOrDefault();
        ClientMessages.setMessagePrefix(config.messagePrefix);

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
        applyChatSender();
        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> chatSendService.tick());
        NeoForge.EVENT_BUS.addListener((ClientPlayerNetworkEvent.LoggingOut event) -> chatSendService.clearPending());
        OptionalClothConfig.registerSaveListener(updated -> {
            ClientMessages.setMessagePrefix(updated.messagePrefix);
            applyChatSender();
        });
        chatReceiveHandler = new ChatReceiveHandler(config, keyStoreService, keyTrustService, cryptoService,
                packetCodec, fragmentService, reassembler, decryptionHistoryService, sessionService,
                sessionHandshakeService, chatSendService::sendPacket, this::system, conversationStore::incoming);
        var optionalSharing = new dev.krypt04mcg.client.OptionalSharing(config, keyStoreService,
                keyTrustService, cryptoService, root);
        optionalSharing.register();
        dataApi = new dev.krypt04mcg.service.DataTransferService(config, keyStoreService, keyTrustService,
                () -> canSend(dev.krypt04mcg.protocol.DataPayload.TYPE), ClientPacketDistributor::sendToServer);
        dev.krypt04mcg.api.Krypt04McgApi.initialize((player, channel, data) -> {
            if (!client.isSameThread()) throw new IllegalStateException("Call the data API on the client thread");
            dataApi.send(player, channel, data);
        });
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
        NeoForge.EVENT_BUS.addListener((ClientPlayerNetworkEvent.LoggingIn event) -> showDisclaimer(Minecraft.getInstance()));
        LOGGER.info("Krypt04Mcg initialized");
    }

    public void openChatScreen() {
        Minecraft client = Minecraft.getInstance();
        if (chatSendService == null || keyStoreService == null || client.player == null) {
            return;
        }
        client.gui.setScreen(new Krypt04McgChatScreen(chatSendService, keyStoreService, groupService, conversationStore));
    }

    private void sendChatLine(ChatSendFragment chatSendFragment) {
        Minecraft client = Minecraft.getInstance();
        String line = chatSendFragment.fragment();
        if (!fragmentService.isFragment(line, config.packetPrefix)) {
            LOGGER.warn("Refusing to send non-Krypt04Mcg chat line");
            return;
        }
        if (client.getConnection() != null) {
            client.getConnection().sendChat(line);
        }
    }

    private void sendServerCommand(ChatSendFragment chatSendFragment) {
        Minecraft client = Minecraft.getInstance();
        String fragment = chatSendFragment.fragment();
        if (!fragmentService.isFragment(fragment, config.packetPrefix)) {
            LOGGER.warn("Refusing to send non-Krypt04Mcg command fragment");
            return;
        }
        if (client.getConnection() != null) {
            client.getConnection().sendCommand(formatServerCommand(config.serverCommandTemplate, chatSendFragment));
        }
    }

    private void applyChatSender() {
        if (chatSendService == null) {
            return;
        }
        if (config.chatSendMode == ChatSendMode.SERVER_COMMAND) {
            chatSendService.setChatSender(this::sendServerCommand);
        } else if (config.chatSendMode == ChatSendMode.CUSTOM_PAYLOAD) {
            chatSendService.setChatSender(this::sendCustomPayload);
        } else {
            chatSendService.setChatSender(this::sendChatLine);
        }
    }

    private void sendCustomPayload(ChatSendFragment chatSendFragment) {
        String fragment = chatSendFragment.fragment();
        if (!fragmentService.isFragment(fragment, config.packetPrefix)) {
            LOGGER.warn("Refusing to send non-Krypt04Mcg payload fragment");
            return;
        }
        if (canSend(NeoChatPayload.TYPE)) {
            ClientPacketDistributor.sendToServer(new NeoChatPayload(
                    chatSendFragment.receiver(), fragment, chatSendFragment.version()));
        } else if (config.verboseMessages) {
            system("Krypt04Mcg payload channel is not available on this server: " + ChatFragmentPayload.CHANNEL);
        }
    }

    private void registerPayloads(RegisterPayloadHandlersEvent event) {
        var registrar = event.registrar("1").optional();
        registrar.playBidirectional(NeoChatPayload.TYPE, NeoChatPayload.CODEC, (payload, context) -> {});
        registrar.playBidirectional(dev.krypt04mcg.protocol.DataPayload.TYPE, dev.krypt04mcg.protocol.DataPayload.CODEC, (payload, context) -> {});
        dev.krypt04mcg.client.OptionalSharing.registerPayloads(registrar);
    }

    private void registerClientPayloads(RegisterClientPayloadHandlersEvent event) {
        event.register(NeoChatPayload.TYPE, (payload, context) -> {
            if (chatReceiveHandler == null) return;
            if (payload.peer().isBlank()) {
                LOGGER.warn("Ignoring Krypt04Mcg payload fragment without a server-authenticated sender");
                return;
            }
            chatReceiveHandler.handle(payload.peer(), payload.fragment());
        });
        event.register(dev.krypt04mcg.protocol.DataPayload.TYPE, (payload, context) ->
                context.enqueueWork(() -> { if (dataApi != null) dataApi.receive(payload); }));
        dev.krypt04mcg.client.OptionalSharing.registerClientPayloads(event);
    }

    private static boolean canSend(net.minecraft.network.protocol.common.custom.CustomPacketPayload.Type<?> type) {
        var connection = Minecraft.getInstance().getConnection();
        return connection != null && NetworkRegistry.hasChannel(connection, type.id());
    }
    static String formatServerCommand(String template, ChatSendFragment fragment) {
        String command = template == null || template.isBlank() ? "/msg <receiver> <fragment>" : template;
        command = command.replace("<receiver>", fragment.receiver())
                .replace("<fragment>", fragment.fragment());
        return command.startsWith("/") ? command.substring(1) : command;
    }

    private void system(String message) {
        Minecraft client = Minecraft.getInstance();
        client.execute(() -> {
            if (client.gui != null) {
                client.gui.hud.getChat().addClientSystemMessage(Component.literal(message));
            }
        });
    }

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

    private List<String> shadowListenRegexes() {
        if (config.shadowListenRegexes != null && !config.shadowListenRegexes.isEmpty()) {
            return config.shadowListenRegexes;
        }
        return List.of(config.shadowListenRegex);
    }

    private static boolean isLocalSender(String senderName, String localName) {
        return senderName != null && localName != null && senderName.equalsIgnoreCase(localName);
    }

    private record ShadowMessage(String player, String message) {
    }
}



