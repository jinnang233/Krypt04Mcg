package dev.krypt04mcg.client;

import com.google.gson.Gson;
import com.mojang.brigadier.arguments.StringArgumentType;
import dev.krypt04mcg.config.*;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.*;
import dev.krypt04mcg.service.*;
import dev.krypt04mcg.util.*;
import net.minecraft.commands.Commands;
import net.neoforged.neoforge.client.event.RegisterClientCommandsEvent;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import net.neoforged.neoforge.client.event.ClientPlayerNetworkEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.client.network.ClientPacketDistributor;
import net.neoforged.neoforge.client.network.event.RegisterClientPayloadHandlersEvent;
import net.neoforged.neoforge.network.registration.NetworkRegistry;
import net.neoforged.neoforge.network.registration.PayloadRegistrar;


import net.minecraft.client.Minecraft;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.*;
import java.nio.file.*;
import java.util.*;
import dev.krypt04mcg.protocol.FileStreamCodec.FileData;
import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.api.KryptSocket;

import static dev.krypt04mcg.client.ClientMessages.tr;

/** Optional, user-initiated transfers. All callbacks run on the client thread. */
public final class OptionalSharing {
    private static OptionalSharing active;
    private final Krypt04McgConfig config;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final CryptoService crypto;
    private final Path root;
    private final Gson gson = JsonSupport.prettyGson();
    private final OptionalTransferAssembler keyParts = new OptionalTransferAssembler(OptionalTransferAssembler.MAX_KEY_CHUNKS, 4);
    private static final String FILE_CHANNEL = "krypt04mcg_file:stream";
    private FileSend outgoing;
    private FileReceiveTask receiving;
    private final Deque<PublicKeyPayload> outgoingKeys = new ArrayDeque<>();
    private final Map<String, Pending> pending = new HashMap<>();
    private final FileSharingLock fileLock;
    private final SharingWorker worker = new SharingWorker();
    private long generation;
    private boolean wasSending, wasReceiving;
    private ChatSendMode previousMode;

    public OptionalSharing(Krypt04McgConfig config, KeyStoreService keys, KeyTrustService trust,
                           CryptoService crypto, Path root) {
        active = this;
        this.config = config; this.keys = keys; this.trust = trust; this.crypto = crypto; this.root = root;
        fileLock = new FileSharingLock(root);
        Krypt04McgApi.registerSocketReceiver(FILE_CHANNEL, this::receiveFile);
        applySettings();
    }

    public void applySettings() {
        if (receiving != null && receiving.expire()) receiving = null;
        if (wasSending != config.enableFileSending || wasReceiving != config.enableFileReceiving
                || previousMode != config.chatSendMode) generation++;
        wasSending = config.enableFileSending; wasReceiving = config.enableFileReceiving;
        previousMode = config.chatSendMode;
        if (config.permanentlyDisableFileSharing && !fileLock.locked()) {
            try { fileLock.disable(); }
            catch (Exception e) { dev.krypt04mcg.Krypt04McgMod.LOGGER.warn("Unable to persist file-sharing lock", e); message(tr("text.krypt04mcg.share.lock_failed")); }
        }
        if (fileLock.locked() || !config.enableFileReceiving) {
            cancelReceiving();
            pending.values().removeIf(p -> p.file != null);
        }
        if (fileLock.locked() || !config.enableFileSending || config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD) cancelOutgoing();
        if (config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD) {
            pending.clear(); keyParts.clear(); cancelReceiving(); outgoingKeys.clear();
        }
    }

    public void register() {
        NeoForge.EVENT_BUS.addListener((ClientPlayerNetworkEvent.LoggingOut event) -> {
            generation++;
            keyParts.clear(); cancelReceiving(); pending.clear(); cancelOutgoing(); outgoingKeys.clear();
        });
        NeoForge.EVENT_BUS.addListener((ClientTickEvent.Post event) -> {
            Minecraft client = Minecraft.getInstance();
            applySettings();
            expire();
            long now = System.currentTimeMillis();
            keyParts.expire(now);
            if (client.getConnection() == null) { cancelOutgoing(); outgoingKeys.clear(); return; }
            if (!canSend(PublicKeyPayload.TYPE)) outgoingKeys.clear();
            for (int i = 0; i < 4 && !outgoingKeys.isEmpty(); i++) {
                PublicKeyPayload payload = outgoingKeys.removeFirst();
                ClientPacketDistributor.sendToServer(payload);
                if (outgoingKeys.isEmpty()) message(tr("text.krypt04mcg.share.key_sent",
                        payload.peer().equals("*") ? tr("text.krypt04mcg.share.everyone") : payload.peer()));
            }
            pumpFile();
        });
        NeoForge.EVENT_BUS.addListener((RegisterClientCommandsEvent event) -> event.getDispatcher().register(
            Commands.literal("k04m-share")
                .then(Commands.literal("key").executes(c -> run(() -> sendKey("*")))
                    .then(Commands.argument("player", StringArgumentType.word())
                    .executes(c -> run(() -> sendKey(StringArgumentType.getString(c, "player"))))))
                .then(Commands.literal("file").then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("path", StringArgumentType.greedyString())
                        .executes(c -> run(() -> sendFile(StringArgumentType.getString(c, "player"), StringArgumentType.getString(c, "path")))))))
                .then(Commands.literal("accept").then(Commands.argument("token", StringArgumentType.word())
                    .executes(c -> run(() -> decide(StringArgumentType.getString(c, "token"), true)))))
                .then(Commands.literal("reject").then(Commands.argument("token", StringArgumentType.word())
                    .executes(c -> run(() -> decide(StringArgumentType.getString(c, "token"), false)))))
                .then(Commands.literal("disable-files").executes(c -> run(() -> {
                    config.permanentlyDisableFileSharing = true;
                    try { fileLock.disable(); }
                    catch (java.io.IOException e) {
                        dev.krypt04mcg.Krypt04McgMod.LOGGER.warn("Unable to persist file-sharing lock", e);
                        throw problem("lock_failed");
                    } finally { applySettings(); }
                    message(tr("text.krypt04mcg.share.disabled"));
                })))));
    }

    public static void registerPayloads(PayloadRegistrar registrar) {
        registrar.playBidirectional(PublicKeyPayload.TYPE, PublicKeyPayload.CODEC, (payload, context) -> {});
    }

    public static void registerClientPayloads(RegisterClientPayloadHandlersEvent event) {
        event.register(PublicKeyPayload.TYPE, (payload, context) -> {
            if (active != null) active.receive(payload.peer(), payload.fragment(), payload.version(), false);
        });
    }

    private static boolean canSend(net.minecraft.network.protocol.common.custom.CustomPacketPayload.Type<?> type) {
        var connection = Minecraft.getInstance().getConnection();
        return connection != null && NetworkRegistry.hasChannel(connection, type.id());
    }
    private void requireMode() {
        if (config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD) throw problem("mode");
    }

    private void sendKey(String player) throws Exception {
        requireMode();
        if (!canSend(PublicKeyPayload.TYPE)) throw problem("key_channel");
        if (!outgoingKeys.isEmpty()) throw problem("busy");
        for (String part : OptionalTransferAssembler.split(gson.toJson(keys.ownPublicIdentity()), OptionalTransferAssembler.MAX_KEY_CHUNKS))
            outgoingKeys.addLast(new PublicKeyPayload(player, part, 1));
    }

    private PublicIdentity trusted(String player) throws Exception {
        PublicIdentity identity = keys.findPublicIdentity(player).orElseThrow(() -> problem("key_required"));
        if (trust.trustState(player, identity) == TrustState.DISTRUSTED) throw problem("distrusted");
        return identity;
    }

    private void sendFile(String player, String path) throws Exception {
        requireMode(); applySettings();
        if (fileLock.locked() || !config.enableFileSending) throw problem("sending_off");
        trusted(player);
        if (path.startsWith("\"") && path.endsWith("\"")) path = path.substring(1, path.length() - 1);
        Path input = Path.of(path);
        if (outgoing != null) throw problem("busy");
        String fingerprint = KeyTrustService.fingerprintPair(trusted(player));
        submit(true, true, () -> FileStreamCodec.encode(input), bytes -> {
            if (!fingerprint.equals(KeyTrustService.fingerprintPair(trusted(player)))) throw problem("distrusted");
            outgoing = new FileSend(Krypt04McgApi.connect(player, FILE_CHANNEL), bytes);
            message(tr("text.krypt04mcg.share.file_queued", player));
        });
    }

    private void pumpFile() {
        if (outgoing == null) return;
        FileSend current = outgoing;
        try {
            if (current.socket.isFailed()) throw new java.io.IOException("File stream failed");
            for (int i = 0; i < 4 && current.offset < current.bytes.length; i++) {
                int count = Math.min(current.socket.writableBytes(),
                        Math.min(RawChannelPayload.MAX_PLAINTEXT, current.bytes.length - current.offset));
                if (count == 0) break;
                current.socket.getOutputStream().write(current.bytes, current.offset, count);
                current.offset += count;
            }
            if (current.offset == current.bytes.length) current.socket.close();
            if (current.socket.outputEnded()) {
                outgoing = null; message(tr("text.krypt04mcg.share.file_sent", current.socket.peer()));
            }
        } catch (Exception e) { cancelOutgoing(); message(tr("text.krypt04mcg.share.failed")); }
    }
    private void cancelOutgoing() { if (outgoing != null) { outgoing.socket.fail("File send cancelled"); outgoing = null; } }
    private void cancelReceiving() { if (receiving != null) { receiving.cancel(); receiving = null; } }
    private String fileIdentity(String peer) throws Exception {
        var local = keys.local();
        return KeyTrustService.fingerprintPair(trusted(peer)) + "/" + local.kemPublicKey().fingerprint()
                + ":" + local.signaturePublicKey().fingerprint();
    }
    private void receiveFile(KryptSocket socket) {
        applySettings(); expire();
        if (fileLock.locked() || !config.enableFileReceiving || config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD
                || worker.busy() || receiving != null || pending.size() >= 4 || pending.values().stream().anyMatch(p -> p.file != null)) {
            socket.fail("File receive unavailable"); return;
        }
        try {
            String fingerprint = fileIdentity(socket.peer());
            var task = new FileReceiveTask(socket);
            receiving = task; socket.close();
            submit(true, false, () -> {
                try { return task.read(); }
                finally { Minecraft.getInstance().execute(() -> { if (receiving == task) receiving = null; }); }
            }, data -> {
                if (!fingerprint.equals(fileIdentity(socket.peer()))) return;
                offer(new Pending(socket.peer(), fingerprint, data, System.currentTimeMillis()),
                        tr("text.krypt04mcg.share.file_offer", socket.peer(), data.name().replaceAll("[\\p{Cntrl}§]", "_"), data.data().length));
            }, false);
        } catch (Exception e) { receiving = null; socket.fail("File receive rejected"); }
    }
    private static final class FileSend {
        final KryptSocket socket; final byte[] bytes; int offset;
        FileSend(KryptSocket socket, byte[] bytes) { this.socket = socket; this.bytes = bytes; }
    }

    private void receive(String sender, String fragment, int version, boolean file) {
        if (file || config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD || version != 1 || !sender.matches("[A-Za-z0-9_]{1,16}")) return;
        applySettings();
        if (worker.busy()) return;
        try {
            expire();
            if (pending.size() >= 4 || pending.values().stream().anyMatch(p -> p.file == null && p.sender.equalsIgnoreCase(sender))) return;
            var assembled = keyParts.accept(sender, fragment, System.currentTimeMillis(), () -> true);
            if (assembled.isEmpty()) return;
            String json = assembled.get();
            submit(false, false, () -> crypto.validatePublicIdentity(gson.fromJson(json, PublicIdentity.class)), identity -> {
                if (!sender.equalsIgnoreCase(identity.owner())) throw problem("owner_mismatch");
                offer(new Pending(sender, gson.toJson(identity), null, System.currentTimeMillis()),
                        tr("text.krypt04mcg.share.key_offer", sender, KeyTrustService.fingerprintPair(identity)));
            }, false);
        } catch (Exception ignored) { }
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
        if (accept && worker.busy()) throw problem("busy");
        expire(); Pending request = pending.remove(token);
        if (request == null) throw problem("expired");
        if (!accept) { message(tr("text.krypt04mcg.share.rejected")); return; }
        requireMode(); applySettings();
        if (request.file == null) {
            PublicIdentity identity = keys.importPublicIdentity(request.sender, request.json);
            trust.rememberTofu(request.sender, identity);
            message(tr("text.krypt04mcg.share.key_accepted", request.sender));
        } else {
            if (fileLock.locked() || !config.enableFileReceiving) throw problem("receiving_off");
            // Revalidate both identities after consent and immediately before the atomic save.
            if (!request.json.equals(fileIdentity(request.sender))) throw problem("distrusted");
            submit(true, false, () -> request.file, data -> {
                if (!request.json.equals(fileIdentity(request.sender))) throw problem("distrusted");
                String name = data.name().replaceAll("[^A-Za-z0-9._-]", "_");
                if (name.length() > 180) name = name.substring(name.length() - 180);
                Path output = root.resolve("received-files").resolve(UUID.randomUUID() + "-" + name);
                SecureFiles.atomicWrite(output, data.data());
                message(tr("text.krypt04mcg.share.saved", output.toAbsolutePath()));
            });
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
    private interface Completion<T> { void accept(T value) throws Exception; }
    private <T> void submit(boolean file, boolean sending, java.util.concurrent.Callable<T> work, Completion<T> completed) {
        submit(file, sending, work, completed, true);
    }

    private <T> void submit(boolean file, boolean sending, java.util.concurrent.Callable<T> work, Completion<T> completed,
                            boolean reportErrors) {
        Minecraft client = Minecraft.getInstance();
        var connection = client.getConnection();
        long epoch = generation;
        if (!worker.submit(work, client::execute, (value, error) -> {
            if (connection != client.getConnection() || epoch != generation || config.chatSendMode != ChatSendMode.CUSTOM_PAYLOAD) return;
            if (file && (fileLock.locked() || !(sending ? config.enableFileSending : config.enableFileReceiving))) return;
            if (!reportErrors) {
                if (error == null) {
                    try { completed.accept(value); } catch (Exception ignored) {}
                }
                return;
            }
            run(() -> {
                if (error != null) throw error;
                completed.accept(value);
            });
        })) throw problem("busy");
    }
    private static SharingProblem problem(String key, Object... args) {
        return new SharingProblem(tr("text.krypt04mcg.share." + key, args));
    }
    private static final class SharingProblem extends RuntimeException {
        private SharingProblem(String translated) { super(translated); }
    }
    private record Pending(String sender, String json, FileData file, long created) {}
}



