package dev.krypt04mcg.client;

import com.google.gson.Gson;
import com.mojang.brigadier.arguments.StringArgumentType;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.service.*;
import dev.krypt04mcg.util.*;
import net.fabricmc.fabric.api.client.command.v2.*;
import net.fabricmc.fabric.api.client.networking.v1.*;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.Minecraft;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.*;
import java.nio.file.*;
import java.util.*;
import dev.krypt04mcg.protocol.FileTransferCodec.FileData;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import static dev.krypt04mcg.client.ClientMessages.tr;

/** Optional, user-initiated transfers. All callbacks run on the client thread. */
public final class OptionalSharing {
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final CryptoService crypto;
    private final Path root;
    private final Gson gson = JsonSupport.prettyGson();
    private final FileTransferCodec files = new FileTransferCodec();
    private final OptionalTransferAssembler keyParts = new OptionalTransferAssembler();
    private final OptionalTransferAssembler fileParts = new OptionalTransferAssembler(FileTransferCodec.MAX_CHUNKS, 1);
    private final Deque<FileSharePayload> outgoing = new ArrayDeque<>();
    private final Map<String, Pending> pending = new HashMap<>();
    private final Set<String> seenFiles = new HashSet<>();
    private boolean locked;

    public OptionalSharing(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                           CryptoService crypto, Path root) {
        this.config = config; this.keys = keys; this.trust = trust; this.crypto = crypto; this.root = root;
        locked = Files.exists(root.resolve("file-sharing.disabled"));
        applySettings();
    }

    public void applySettings() {
        if (config.permanentlyDisableFileSharing && !locked) {
            locked = true;
            try { SecureFiles.atomicWrite(root.resolve("file-sharing.disabled"), new byte[]{1}); }
            catch (Exception e) { dev.krypt04mcg.Krypt04McgMod.LOGGER.warn("Unable to persist file-sharing lock", e); message(tr("text.krypt04mcg.share.lock_failed")); }
        }
        if (locked || !config.enableFileReceiving) {
            fileParts.clear();
            pending.values().removeIf(p -> p.file != null);
        }
        if (locked || !config.enableFileSending || config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD) outgoing.clear();
    }

    public void register() {
        PayloadTypeRegistry.serverboundPlay().register(PublicKeyPayload.TYPE, PublicKeyPayload.CODEC);
        PayloadTypeRegistry.clientboundPlay().register(PublicKeyPayload.TYPE, PublicKeyPayload.CODEC);
        PayloadTypeRegistry.serverboundPlay().register(FileSharePayload.TYPE, FileSharePayload.CODEC);
        PayloadTypeRegistry.clientboundPlay().register(FileSharePayload.TYPE, FileSharePayload.CODEC);
        ClientPlayNetworking.registerGlobalReceiver(PublicKeyPayload.TYPE,
                (p, c) -> c.client().execute(() -> receive(p.peer(), p.fragment(), p.version(), false)));
        ClientPlayNetworking.registerGlobalReceiver(FileSharePayload.TYPE,
                (p, c) -> c.client().execute(() -> receive(p.peer(), p.fragment(), p.version(), true)));
        ClientPlayConnectionEvents.DISCONNECT.register((h, c) -> {
            keyParts.clear(); fileParts.clear(); pending.clear(); seenFiles.clear(); outgoing.clear();
        });
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            applySettings();
            if (client.getConnection() == null) { outgoing.clear(); return; }
            if (!ClientPlayNetworking.canSend(FileSharePayload.TYPE)) outgoing.clear();
            // Pace large transfers instead of sending thousands of packets in one tick.
            for (int i = 0; i < 4 && !outgoing.isEmpty(); i++) {
                FileSharePayload payload = outgoing.removeFirst();
                ClientPlayNetworking.send(payload);
                if (outgoing.isEmpty()) message(tr("text.krypt04mcg.share.file_sent", payload.peer()));
            }
        });
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registry) -> dispatcher.register(
            ClientCommands.literal("k04m-share")
                .then(ClientCommands.literal("key").executes(c -> run(() -> sendKey("*")))
                    .then(ClientCommands.argument("player", StringArgumentType.word())
                    .executes(c -> run(() -> sendKey(StringArgumentType.getString(c, "player"))))))
                .then(ClientCommands.literal("file").then(ClientCommands.argument("player", StringArgumentType.word())
                    .then(ClientCommands.argument("path", StringArgumentType.greedyString())
                        .executes(c -> run(() -> sendFile(StringArgumentType.getString(c, "player"), StringArgumentType.getString(c, "path")))))))
                .then(ClientCommands.literal("accept").then(ClientCommands.argument("token", StringArgumentType.word())
                    .executes(c -> run(() -> decide(StringArgumentType.getString(c, "token"), true)))))
                .then(ClientCommands.literal("reject").then(ClientCommands.argument("token", StringArgumentType.word())
                    .executes(c -> run(() -> decide(StringArgumentType.getString(c, "token"), false)))))
                .then(ClientCommands.literal("disable-files").executes(c -> run(() -> {
                    config.permanentlyDisableFileSharing = true; applySettings(); message(tr("text.krypt04mcg.share.disabled"));
                })))));
    }

    private void requireMode() {
        if (config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD) throw problem("mode");
    }

    private void sendKey(String player) throws Exception {
        requireMode();
        if (!ClientPlayNetworking.canSend(PublicKeyPayload.TYPE)) throw problem("key_channel");
        for (String part : OptionalTransferAssembler.split(gson.toJson(keys.ownPublicIdentity())))
            ClientPlayNetworking.send(new PublicKeyPayload(player, part, 1));
        message(tr("text.krypt04mcg.share.key_sent", player.equals("*") ? tr("text.krypt04mcg.share.everyone") : player));
    }

    private PublicIdentity trusted(String player) throws Exception {
        PublicIdentity identity = keys.findPublicIdentity(player).orElseThrow(() -> problem("key_required"));
        if (trust.trustState(player, identity) == TrustState.DISTRUSTED) throw problem("distrusted");
        return identity;
    }

    private void sendFile(String player, String path) throws Exception {
        requireMode(); applySettings();
        if (locked || !config.enableFileSending) throw problem("sending_off");
        if (!ClientPlayNetworking.canSend(FileSharePayload.TYPE)) throw problem("file_channel");
        PublicIdentity receiver = trusted(player);
        if (path.startsWith("\"") && path.endsWith("\"")) path = path.substring(1, path.length() - 1);
        Path input = Path.of(path);
        byte[] bytes;
        if (!outgoing.isEmpty()) throw problem("busy");
        try (var stream = Files.newInputStream(input)) { bytes = stream.readNBytes(FileTransferCodec.MAX_FILE_BYTES + 1); }
        if (bytes.length > FileTransferCodec.MAX_FILE_BYTES) throw problem("too_large", 10);
        String envelope = files.encrypt(input.getFileName().toString(), bytes, receiver, keys.local(), config.aeadAlgorithm);
        for (String part : OptionalTransferAssembler.split(envelope, FileTransferCodec.MAX_CHUNKS))
            outgoing.addLast(new FileSharePayload(player, part, 1));
        message(tr("text.krypt04mcg.share.file_queued", player));
    }

    private void receive(String sender, String fragment, int version, boolean file) {
        if (config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD || version != 1 || !sender.matches("[A-Za-z0-9_]{1,16}")) return;
        applySettings();
        if (file && (locked || !config.enableFileReceiving)) return;
        run(() -> {
            expire();
            if (file && pending.values().stream().anyMatch(p -> p.file != null)) return;
            Optional<String> assembled = (file ? fileParts : keyParts).accept(sender, fragment, System.currentTimeMillis());
            if (assembled.isEmpty()) return;
            expire();
            if (pending.size() >= 4) return;
            String json = assembled.get();
            if (!file) {
                PublicIdentity identity = crypto.validatePublicIdentity(gson.fromJson(json, PublicIdentity.class));
                if (!sender.equalsIgnoreCase(identity.owner())) throw problem("owner_mismatch");
                if (pending.values().stream().anyMatch(p -> p.file == null && p.sender.equalsIgnoreCase(sender))) return;
                offer(new Pending(sender, gson.toJson(identity), null, System.currentTimeMillis()),
                    tr("text.krypt04mcg.share.key_offer", sender, KeyTrustService.fingerprintPair(identity)));
            } else {
                long now = System.currentTimeMillis();
                var packet = files.packet(json, sender, now);
                String id = sender + ":" + Base64Url.encode(packet.messageId());
                if (seenFiles.contains(id) || seenFiles.size() >= 1024) return;
                FileData data = files.decrypt(packet, keys.local(), trusted(sender));
                byte[] bytes = Base64Url.decode(data.data());
                seenFiles.add(id);
                offer(new Pending(sender, json, data, now), tr("text.krypt04mcg.share.file_offer", sender,
                    data.name().replaceAll("[\\p{Cntrl}§]", "_"), bytes.length));
            }
        });
    }

    private void expire() { pending.values().removeIf(p -> System.currentTimeMillis() - p.created > 60000); }

    private void offer(Pending request, String text) {
        String token = UUID.randomUUID().toString(); pending.put(token, request);
        var line = Component.literal(ClientMessages.messagePrefixWithSpace() + text + " ");
        line.append(Component.literal(tr("text.krypt04mcg.share.accept")).withStyle(s -> s.withColor(ChatFormatting.GREEN)
                .withClickEvent(new ClickEvent.RunCommand("/k04m-share accept " + token))));
        line.append(Component.literal(" "));
        line.append(Component.literal(tr("text.krypt04mcg.share.reject")).withStyle(s -> s.withColor(ChatFormatting.RED)
                .withClickEvent(new ClickEvent.RunCommand("/k04m-share reject " + token))));
        Minecraft.getInstance().gui.hud.getChat().addClientSystemMessage(line);
    }

    private void decide(String token, boolean accept) throws Exception {
        expire(); Pending request = pending.remove(token);
        if (request == null) throw problem("expired");
        if (!accept) { message(tr("text.krypt04mcg.share.rejected")); return; }
        requireMode(); applySettings();
        if (request.file == null) {
            PublicIdentity identity = keys.importPublicIdentity(request.sender, request.json);
            trust.rememberTofu(request.sender, identity);
            message(tr("text.krypt04mcg.share.key_accepted", request.sender));
        } else {
            if (locked || !config.enableFileReceiving) throw problem("receiving_off");
            // Recheck trust and signature at consent time, since the user may have changed trust.
            files.decrypt(files.packet(request.json, request.sender, System.currentTimeMillis()), keys.local(), trusted(request.sender));
            String name = request.file.name().replaceAll("[^A-Za-z0-9._-]", "_");
            if (name.length() > 180) name = name.substring(name.length() - 180);
            Path output = root.resolve("received-files").resolve(UUID.randomUUID() + "-" + name);
            SecureFiles.atomicWrite(output, Base64Url.decode(request.file.data()));
            message(tr("text.krypt04mcg.share.saved", output.toAbsolutePath()));
        }
    }

    private int run(Action action) {
        try { action.run(); return 1; }
        catch (SharingProblem e) { message(e.getMessage()); return 0; }
        catch (Exception e) {
            dev.krypt04mcg.Krypt04McgMod.LOGGER.warn("Optional sharing failed", e);
            message(tr("text.krypt04mcg.share.failed")); return 0;
        }
    }
    private static void message(String text) {
        Minecraft client = Minecraft.getInstance();
        client.execute(() -> client.gui.hud.getChat().addClientSystemMessage(Component.literal(ClientMessages.messagePrefixWithSpace() + text)));
    }
    private interface Action { void run() throws Exception; }
    private static SharingProblem problem(String key, Object... args) {
        return new SharingProblem(tr("text.krypt04mcg.share." + key, args));
    }
    private static final class SharingProblem extends RuntimeException {
        private SharingProblem(String translated) { super(translated); }
    }
    private record Pending(String sender, String json, FileData file, long created) {}
}

