package dev.krypt04mcg.chat;

import com.google.gson.Gson;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.CachedSentMessage;
import dev.krypt04mcg.model.ChatSendFragment;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.model.SessionMessagePayload;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SentMessageCacheService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.util.JsonSupport;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.BooleanSupplier;

public final class ChatSendService {
    private final Krypt04McgConfig config;
    private final KeyStoreService keyStoreService;
    private final KeyTrustService keyTrustService;
    private final SessionService sessionService;
    private final SessionHandshakeService sessionHandshakeService;
    private final SentMessageCacheService sentMessageCacheService;
    private final CryptoService cryptoService;
    private final PacketCodec packetCodec;
    private final FragmentService fragmentService;
    private final Gson gson = JsonSupport.prettyGson();
    private Consumer<ChatSendFragment> chatSender;
    private Consumer<ChatSendFragment> customPayloadSender;
    private BooleanSupplier customPayloadAvailable = () -> false;
    private final Consumer<String> system;
    private final FragmentSendQueue sendQueue;

    /**
     * Creates a chat send service with the supplied dependencies and initial state.
     *
     * @param config the config supplied to this operation
     * @param keyStoreService the key store service supplied to this operation
     * @param keyTrustService the key trust service supplied to this operation
     * @param sessionService the session service supplied to this operation
     * @param sessionHandshakeService the session handshake service supplied to this operation
     * @param sentMessageCacheService the sent message cache service supplied to this operation
     * @param cryptoService the crypto service supplied to this operation
     * @param packetCodec the packet encoding and decoding collaborator
     * @param fragmentService the fragment service supplied to this operation
     * @param chatSender the chat sender supplied to this operation
     * @param system the system supplied to this operation
     * @param connection the connection supplied to this operation
     */
    public ChatSendService(Krypt04McgConfig config, KeyStoreService keyStoreService, KeyTrustService keyTrustService,
                           SessionService sessionService, SessionHandshakeService sessionHandshakeService,
                           SentMessageCacheService sentMessageCacheService,
                           CryptoService cryptoService, PacketCodec packetCodec, FragmentService fragmentService,
                           Consumer<ChatSendFragment> chatSender, Consumer<String> system,
                           java.util.function.Supplier<?> connection) {
        this.config = config;
        this.keyStoreService = keyStoreService;
        this.keyTrustService = keyTrustService;
        this.sessionService = sessionService;
        this.sessionHandshakeService = sessionHandshakeService;
        this.sentMessageCacheService = sentMessageCacheService;
        this.cryptoService = cryptoService;
        this.packetCodec = packetCodec;
        this.fragmentService = fragmentService;
        this.chatSender = Objects.requireNonNull(chatSender, "chatSender");
        this.system = system;
        this.sendQueue = new FragmentSendQueue(connection, System::nanoTime);
    }

    /**
     * Updates the chat sender used by the encrypted chat send service.
     *
     * @param chatSender the chat sender supplied to this operation
     */
    public void setChatSender(Consumer<ChatSendFragment> chatSender) {
        clearPending();
        this.chatSender = Objects.requireNonNull(chatSender, "chatSender");
    }

    /**
     * Updates the custom payload transport used by the encrypted chat send service.
     *
     * @param sender the sender or source associated with this operation
     * @param available the available supplied to this operation
     */
    public void setCustomPayloadTransport(Consumer<ChatSendFragment> sender, BooleanSupplier available) {
        clearPending();
        this.customPayloadSender = Objects.requireNonNull(sender);
        this.customPayloadAvailable = Objects.requireNonNull(available);
    }

    /**
     * Performs the clear pending operation for the encrypted chat send service.
     */
    public void clearPending() {
        sendQueue.clear();
    }

    /**
     * Updates the progress listener used by the encrypted chat send service.
     *
     * @param progress the progress supplied to this operation
     */
    public void setProgressListener(Consumer<TransferProgressTracker.Update> progress) {
        sendQueue.setProgressListener(progress);
    }

    /**
     * Processes the next scheduled work and lifecycle checks for the encrypted chat send service.
     */
    public void tick() {
        try {
            sendQueue.tick(config.chatSendMode, config.sendDelayMs);
        } catch (Exception e) {
            error(e);
        }
    }

    /**
     * Submits kem message through the encrypted chat send service path. Local submission does not by
     * itself acknowledge remote receipt.
     *
     * @param receiver the intended recipient associated with this operation
     * @param message the message supplied to this operation
     * @param sign whether a signature is added to the encrypted packet
     * @return whether the condition or operation described above succeeds
     */
    public boolean sendKemMessage(String receiver, String message, boolean sign) {
        try {
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
            ensureSendAllowed(receiver, identity);
            EncryptedPacket packet = cryptoService.encryptFor(identity, keyStoreService.local(),
                    keyStoreService.local().kemPublicKey().owner(), message, sign, config.enableCompression,
                    config.aeadAlgorithm);
            sendPacket(packet, receiver);
            reportQueuedMessage(receiver, message);
            return true;
        } catch (Exception e) {
            error(e);
            return false;
        }
    }

    /**
     * Returns the recorded true for the encrypted chat send service.
     *
     * @param receiver the intended recipient associated with this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean exchange(String receiver) {
        try {
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
            ensureSendAllowed(receiver, identity);
            EncryptedPacket packet = sessionHandshakeService.begin(identity, keyStoreService.local(),
                    config.ephemeralKemAlgorithm, config.enableCompression, config.aeadAlgorithm);
            sendPacket(packet, receiver);
            system.accept(ClientMessages.tr("text.krypt04mcg.session_prepared", receiver));
            return true;
        } catch (Exception e) {
            error(e);
            return false;
        }
    }

    /**
     * Submits session message through the encrypted chat send service path. Local submission does not by
     * itself acknowledge remote receipt.
     *
     * @param receiver the intended recipient associated with this operation
     * @param message the message supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean sendSessionMessage(String receiver, String message) {
        try {
            SessionRecord session = sessionService.find(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_session", receiver)));
            if (sessionService.isExpired(session, config.sessionTtlMinutes, config.maxMessagesPerSession, config.rotateAfterBytes)) {
                throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.session_expired", receiver));
            }
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
            ensureSendAllowed(receiver, identity);
            String peerFingerprint = KeyTrustService.fingerprintPair(identity);
            if (!session.peerFingerprint().equalsIgnoreCase(peerFingerprint)) {
                throw new IllegalStateException("Session identity binding no longer matches " + receiver);
            }
            if (!KeyTrustService.fingerprintPair(keyStoreService.ownPublicIdentity())
                    .equalsIgnoreCase(session.localFingerprint())) {
                throw new IllegalStateException("Session local identity changed; exchange a new session");
            }
            long sequence = session.nextSendSequence();
            String payload = gson.toJson(new SessionMessagePayload(SessionMessagePayload.VERSION,
                    message));
            EncryptedPacket packet = cryptoService.encryptWithSession(identity.owner(),
                    keyStoreService.local().kemPublicKey().owner(), Base64Url.decode(session.secret()),
                    session.sessionId(), sequence, payload, config.enableCompression, config.aeadAlgorithm);
            sendPacket(packet, receiver);
            sessionService.recordSentMessage(receiver, sequence,
                    message.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            reportQueuedMessage(receiver, message);
            return true;
        } catch (Exception e) {
            error(e);
            return false;
        }
    }

    /**
     * Submits group message through the encrypted chat send service path. Local submission does not by
     * itself acknowledge remote receipt.
     *
     * @param groupName the group name supplied to this operation
     * @param members the members supplied to this operation
     * @param message the message supplied to this operation
     */
    public void sendGroupMessage(String groupName, List<String> members, String message) {
        if (members.isEmpty()) {
            system.accept(ClientMessages.tr("text.krypt04mcg.error.group_empty", groupName));
            return;
        }
        system.accept(ClientMessages.tr("text.krypt04mcg.group_sending", groupName, members.size()));
        for (String member : members) {
            sendKemMessage(member, message, true);
        }
    }

    /**
     * Performs the resend latest operation for the encrypted chat send service.
     */
    public void resendLatest() {
        try {
            CachedSentMessage cached = sentMessageCacheService.latest()
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_cached_message")));
            resend(cached);
        } catch (Exception e) {
            error(e);
        }
    }

    /**
     * Performs the resend operation for the encrypted chat send service.
     *
     * @param messageId the message identifier used for correlation or key-derivation context
     */
    public void resend(String messageId) {
        try {
            CachedSentMessage cached = sentMessageCacheService.find(messageId)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_cached_message_id", messageId)));
            resend(cached);
        } catch (Exception e) {
            error(e);
        }
    }

    /**
     * Performs the resend operation for the encrypted chat send service.
     *
     * @param cached the cached supplied to this operation
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private void resend(CachedSentMessage cached) throws Exception {
        PublicIdentity identity = keyStoreService.findPublicIdentity(cached.receiver())
                .orElseThrow(() -> new IllegalStateException(
                        ClientMessages.tr("text.krypt04mcg.error.no_public_key", cached.receiver())));
        ensureSendAllowed(cached.receiver(), identity);
        ensureRecipientMatches(cached.receiver(), identity, cached.recipientFingerprint());
        sendFragments(cached.receiver(), cached.fragments(), cached.recipientFingerprint());
        system.accept(ClientMessages.tr("text.krypt04mcg.resending", cached.receiver(), cached.messageId()));
    }

    /**
     * Submits packet through the encrypted chat send service path. Local submission does not by itself
     * acknowledge remote receipt.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param receiver the intended recipient associated with this operation
     * @throws Exception if the delegated operation cannot complete successfully
     */
    public void sendPacket(EncryptedPacket packet, String receiver) throws Exception {
        PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                .orElseThrow(() -> new IllegalStateException(
                        ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
        if (keyTrustService.trustState(receiver, identity) == TrustState.DISTRUSTED) {
            throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", receiver));
        }
        String recipientFingerprint = KeyTrustService.fingerprintPair(identity);
        byte[] encoded = packetCodec.encode(packet);
        List<String> fragments = fragmentService.fragment(encoded, packet.messageId(), config.fragmentSize, config.packetPrefix);
        sentMessageCacheService.remember(Hex.encode(packet.messageId()), receiver, fragments, recipientFingerprint);
        sendFragments(receiver, fragments, recipientFingerprint);
    }

    /**
     * Submits fragments through the encrypted chat send service path. Local submission does not by itself
     * acknowledge remote receipt.
     *
     * @param receiver the intended recipient associated with this operation
     * @param fragments the fragments supplied to this operation
     * @param recipientFingerprint the recipient fingerprint supplied to this operation
     */
    private void sendFragments(String receiver, List<String> fragments, String recipientFingerprint) {
        ChatSendPolicy.Plan plan = ChatSendPolicy.plan(config.chatSendMode, config.sendDelayMs,
                config.maxPacketAgeSeconds, fragments.size(), customPayloadAvailable.getAsBoolean());
        Consumer<ChatSendFragment> sender = plan.customPayload() && customPayloadSender != null
                ? customPayloadSender : chatSender;
        sendQueue.enqueue(receiver, fragments, fragment -> {
            try {
                PublicIdentity current = keyStoreService.findPublicIdentity(receiver).orElse(null);
                ensureRecipientMatches(receiver, current, recipientFingerprint);
                if (keyTrustService.trustState(receiver, current) == TrustState.DISTRUSTED) {
                    throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", receiver));
                }
            } catch (Exception e) {
                // Queue transport failure cancels the remaining fragments, rather than retrying stale ciphertext.
                throw new IllegalStateException(e.getMessage(), e);
            }
            sender.accept(fragment);
        }, plan.delayMillis(), plan.queueBudgetMillis());
    }

    /**
     * Checks the recipient matches required by the encrypted chat send service and rejects invalid state
     * instead of continuing.
     *
     * @param receiver the intended recipient associated with this operation
     * @param identity the identity supplied to this operation
     * @param fingerprint the fingerprint supplied to this operation
     */
    private void ensureRecipientMatches(String receiver, PublicIdentity identity, String fingerprint) {
        // Legacy cache entries have no identity binding and cannot be safely resent.
        if (!keyTrustService.fingerprintMatches(identity, fingerprint)) {
            throw new IllegalStateException("Cached message recipient identity no longer matches " + receiver
                    + "; send a new message");
        }
    }

    /**
     * Checks the send allowed required by the encrypted chat send service and rejects invalid state
     * instead of continuing.
     *
     * @param receiver the intended recipient associated with this operation
     * @param identity the identity supplied to this operation
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private void ensureSendAllowed(String receiver, PublicIdentity identity) throws Exception {
        TrustState trustState = keyTrustService.trustState(receiver, identity);
        if (trustState == TrustState.DISTRUSTED) {
            throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", receiver));
        }
        if (trustState == TrustState.TOFU_TRUSTED) {
            system.accept(ClientMessages.tr("text.krypt04mcg.warning.tofu_unverified", identity.owner()));
        }
    }

    /**
     * Performs the report queued message operation for the encrypted chat send service.
     *
     * @param receiver the intended recipient associated with this operation
     * @param message the message supplied to this operation
     */
    private void reportQueuedMessage(String receiver, String message) {
        system.accept(config.showSentPlaintext
                ? ClientMessages.tr("text.krypt04mcg.sent_plaintext",
                        keyStoreService.local().kemPublicKey().owner(), receiver, message)
                : ClientMessages.tr("text.krypt04mcg.sent_encrypted", receiver));
    }

    /**
     * Performs the error operation for the encrypted chat send service.
     *
     * @param e the e supplied to this operation
     */
    private void error(Exception e) {
        system.accept(ClientMessages.tr("text.krypt04mcg.error.generic", e.getMessage()));
    }

}
