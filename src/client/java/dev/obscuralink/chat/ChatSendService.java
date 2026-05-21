package dev.obscuralink.chat;

import dev.obscuralink.config.ObscuraLinkConfig;
import dev.obscuralink.crypto.CryptoService;
import dev.obscuralink.fragment.FragmentService;
import dev.obscuralink.model.EncryptedPacket;
import dev.obscuralink.model.PublicIdentity;
import dev.obscuralink.model.SessionRecord;
import dev.obscuralink.protocol.PacketCodec;
import dev.obscuralink.service.KeyStoreService;
import dev.obscuralink.service.SessionService;

import java.util.List;
import java.util.function.Consumer;

public final class ChatSendService {
    private final ObscuraLinkConfig config;
    private final KeyStoreService keyStoreService;
    private final SessionService sessionService;
    private final CryptoService cryptoService;
    private final PacketCodec packetCodec;
    private final FragmentService fragmentService;
    private final Consumer<String> chatSender;
    private final Consumer<String> system;

    public ChatSendService(ObscuraLinkConfig config, KeyStoreService keyStoreService, SessionService sessionService,
                           CryptoService cryptoService, PacketCodec packetCodec, FragmentService fragmentService,
                           Consumer<String> chatSender, Consumer<String> system) {
        this.config = config;
        this.keyStoreService = keyStoreService;
        this.sessionService = sessionService;
        this.cryptoService = cryptoService;
        this.packetCodec = packetCodec;
        this.fragmentService = fragmentService;
        this.chatSender = chatSender;
        this.system = system;
    }

    public void sendKemMessage(String receiver, String message, boolean sign) {
        try {
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException("No public key for " + receiver + ". Use /enc key import first."));
            EncryptedPacket packet = cryptoService.encryptFor(identity, keyStoreService.local(),
                    keyStoreService.local().kemPublicKey().owner(), message, sign);
            sendPacket(packet);
            system.accept("[ObscuraLink] Sent encrypted message to " + receiver + ".");
        } catch (Exception e) {
            system.accept("[ObscuraLink][ERROR] " + e.getMessage());
        }
    }

    public void exchange(String receiver) {
        try {
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException("No public key for " + receiver + ". Use /enc key import first."));
            SessionRecord record = sessionService.createLocalSession(receiver, identity.kemPublicKey().fingerprint());
            sendKemMessage(receiver, "/session " + record.sessionId() + " " + record.secret(), true);
            system.accept("[ObscuraLink] Session material prepared for " + receiver + ".");
        } catch (Exception e) {
            system.accept("[ObscuraLink][ERROR] " + e.getMessage());
        }
    }

    public void sendSessionMessage(String receiver, String message) {
        // The current transport sends session payloads through the same authenticated KEM envelope.
        // Session records are persisted and command-compatible; a future packet type can swap in direct PSK AEAD.
        sendKemMessage(receiver, message, true);
    }

    private void sendPacket(EncryptedPacket packet) {
        byte[] encoded = packetCodec.encode(packet);
        List<String> fragments = fragmentService.fragment(encoded, packet.messageId(), config.fragmentSize);
        Thread sender = new Thread(() -> {
            for (String fragment : fragments) {
                chatSender.accept(fragment);
                if (config.showProgress) {
                    system.accept("[ObscuraLink] Fragment sent.");
                }
                sleep(config.sendDelayMs);
            }
        }, "ObscuraLink Sender");
        sender.setDaemon(true);
        sender.start();
    }

    private static void sleep(int millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
