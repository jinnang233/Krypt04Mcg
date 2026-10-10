package dev.krypt04mcg.chat;

import com.google.gson.Gson;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.model.FragmentProgress;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionMessagePayload;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.Hex;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class ChatReceiveHandler {
    private final Krypt04McgConfig config;
    private final KeyStoreService keyStoreService;
    private final KeyTrustService keyTrustService;
    private final CryptoService cryptoService;
    private final PacketCodec packetCodec;
    private final FragmentService fragmentService;
    private final FragmentReassembler reassembler;
    private final DecryptionHistoryService decryptionHistoryService;
    private final SessionService sessionService;
    private final SessionHandshakeService sessionHandshakeService;
    private final SessionHandshakeService.PacketSender packetSender;
    private final Gson gson = JsonSupport.prettyGson();
    private final Consumer<String> system;
    private final BiConsumer<String, String> decryptedMessageSink;
    private Consumer<TransferProgressTracker.Update> progress = ignored -> {};

    /**
     * Creates a chat receive handler with the supplied dependencies and initial state.
     *
     * @param config the config supplied to this operation
     * @param keyStoreService the key store service supplied to this operation
     * @param keyTrustService the key trust service supplied to this operation
     * @param cryptoService the crypto service supplied to this operation
     * @param packetCodec the packet encoding and decoding collaborator
     * @param fragmentService the fragment service supplied to this operation
     * @param reassembler the reassembler supplied to this operation
     * @param decryptionHistoryService the decryption history service supplied to this operation
     * @param sessionService the session service supplied to this operation
     * @param sessionHandshakeService the session handshake service supplied to this operation
     * @param packetSender the packet sender supplied to this operation
     * @param system the system supplied to this operation
     * @param decryptedMessageSink the decrypted message sink supplied to this operation
     */
    public ChatReceiveHandler(Krypt04McgConfig config, KeyStoreService keyStoreService,
                              KeyTrustService keyTrustService, CryptoService cryptoService,
                              PacketCodec packetCodec, FragmentService fragmentService,
                              FragmentReassembler reassembler, DecryptionHistoryService decryptionHistoryService,
                              SessionService sessionService, SessionHandshakeService sessionHandshakeService,
                              SessionHandshakeService.PacketSender packetSender, Consumer<String> system,
                              BiConsumer<String, String> decryptedMessageSink) {
        this.config = config;
        this.keyStoreService = keyStoreService;
        this.keyTrustService = keyTrustService;
        this.cryptoService = cryptoService;
        this.packetCodec = packetCodec;
        this.fragmentService = fragmentService;
        this.reassembler = reassembler;
        this.decryptionHistoryService = decryptionHistoryService;
        this.sessionService = sessionService;
        this.sessionHandshakeService = sessionHandshakeService;
        this.packetSender = packetSender;
        this.system = system;
        this.decryptedMessageSink = decryptedMessageSink;
        if (reassembler != null) reassembler.setTimeoutListener(this::timedOut);
    }

    /**
     * Performs the should hide operation for the authenticated chat receive handler.
     *
     * @param raw the raw supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean shouldHide(String raw) {
        return config.hideEncryptedRawMessage && extractFragmentLine(raw).isPresent();
    }

    /**
     * Updates the progress listener used by the authenticated chat receive handler.
     *
     * @param progress the progress supplied to this operation
     */
    public void setProgressListener(Consumer<TransferProgressTracker.Update> progress) {
        this.progress = Objects.requireNonNull(progress);
    }

    /**
     * Processes the next scheduled work and lifecycle checks for the authenticated chat receive handler.
     */
    public void tick() {
        reassembler.cleanupTimedOut();
    }

    /**
     * Performs the timed out operation for the authenticated chat receive handler.
     *
     * @param timeout the configured expiry interval
     */
    private void timedOut(FragmentProgress timeout) {
        int separator = timeout.messageId().indexOf(':');
        String peer = separator < 0 ? "unknown" : timeout.messageId().substring(0, separator);
        report(timeout.messageId(), peer.equals("signed-unbound") ? "unknown" : peer,
                timeout.received(), timeout.total(), TransferProgressTracker.Status.TIMED_OUT);
    }

    /**
     * Performs the clear pending operation for the authenticated chat receive handler.
     */
    public void clearPending() {
        reassembler.clear();
    }

    /**
     * Performs the report operation for the authenticated chat receive handler.
     *
     * @param id the id supplied to this operation
     * @param peer the peer identifier associated with this operation
     * @param completed the completed supplied to this operation
     * @param total the total supplied to this operation
     * @param status the status supplied to this operation
     */
    private void report(String id, String peer, int completed, int total, TransferProgressTracker.Status status) {
        progress.accept(new TransferProgressTracker.Update(TransferProgressTracker.Direction.RECEIVE,
                id, peer, completed, total, status));
    }

    /**
     * Extracts and validates sender-bound fragments, performs bounded reassembly, then decodes and
     * authenticates the complete packet before marking receive progress complete. Trust, transport
     * identity, freshness and replay/session checks are applied in their implemented order; unbound shadow
     * chat uses one shared admission bucket.
     *
     * @param transportSender the source identity supplied by the transport, not the unauthenticated body
     * @param raw the raw supplied to this operation
     */
    public void handle(String transportSender, String raw) {
        Optional<String> fragmentLine = extractFragmentLine(raw);
        if (fragmentLine.isEmpty()) {
            return;
        }
        String displaySender = transportSender == null || transportSender.isBlank() ? "unknown" : transportSender;
        String reassemblyId = null;
        int received = 0;
        int total = 0;
        try {
            tick();
            Fragment fragment = fragmentService.parse(fragmentLine.get(), config.packetPrefix);
            String source = normalizeTransportSender(transportSender);
            reassemblyId = source + ":" + fragment.messageId().toLowerCase(Locale.ROOT);
            total = fragment.total();
            Fragment senderBoundFragment = new Fragment(reassemblyId, fragment.index(), fragment.total(), fragment.payload());
            Optional<byte[]> packetBytes = reassembler.accept(senderBoundFragment, source);
            if (packetBytes.isEmpty()) {
                var counts = reassembler.progress(reassemblyId);
                if (counts.isPresent()) {
                    report(reassemblyId, displaySender, counts.get().received(), counts.get().total(),
                            TransferProgressTracker.Status.TRANSFERRING);
                }
                return;
            }
            received = total;
            report(reassemblyId, displaySender, received, total, TransferProgressTracker.Status.VERIFYING);
            EncryptedPacket packet = packetCodec.decode(packetBytes.get());
            if (!fragment.messageId().equalsIgnoreCase(Hex.encode(packet.messageId()))) {
                throw new IllegalArgumentException("Fragment message ID does not match the encrypted packet");
            }
            requireTransportIdentity(transportSender, packet);
            if (!packet.receiver().equalsIgnoreCase(keyStoreService.local().kemPublicKey().owner())) {
                report(reassemblyId, displaySender, received, total, TransferProgressTracker.Status.CANCELLED);
                if (config.verboseMessages) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.ignored_packet", packet.receiver()));
                }
                return;
            }
            if (keyTrustService.trustState(packet.sender(), null) == TrustState.DISTRUSTED) {
                throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", packet.sender()));
            }
            PublicIdentity sender = keyStoreService.findPublicIdentity(packet.sender())
                    .orElseThrow(() -> new IllegalStateException(
                            ClientMessages.tr("text.krypt04mcg.error.no_sender_public_key", packet.sender())));
            TrustState trustState = keyTrustService.trustState(packet.sender(), sender);
            if (trustState == TrustState.DISTRUSTED) {
                throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", packet.sender()));
            }

            SessionHandshakeService.DecryptedExchange exchange = null;
            SessionMessagePayload sessionMessage = null;
            String plaintext;
            switch (packet.type()) {
                case KEM_MESSAGE, SIGNED_KEM_MESSAGE ->
                        plaintext = cryptoService.decrypt(packet, keyStoreService.local(), sender);
                case SESSION_EXCHANGE -> {
                    exchange = sessionHandshakeService.decrypt(packet, keyStoreService.local(), sender);
                    plaintext = exchange.plaintext();
                }
                case SESSION_MESSAGE -> {
                    SessionRecord session = sessionService.find(packet.sender())
                            .orElseThrow(() -> new IllegalStateException(
                                    ClientMessages.tr("text.krypt04mcg.error.no_session", packet.sender())));
                    if (sessionService.isExpired(session, config.sessionTtlMinutes,
                            config.maxMessagesPerSession, config.rotateAfterBytes)) {
                        throw new IllegalStateException(ClientMessages.tr(
                                "text.krypt04mcg.error.session_expired", packet.sender()));
                    }
                    if (!session.peerFingerprint().equalsIgnoreCase(KeyTrustService.fingerprintPair(sender))) {
                        throw new IllegalStateException("Session identity binding mismatch for " + packet.sender());
                    }
                    if (!KeyTrustService.fingerprintPair(keyStoreService.ownPublicIdentity())
                            .equalsIgnoreCase(session.localFingerprint())) {
                        throw new IllegalStateException("Session local identity changed; exchange a new session");
                    }
                    String decrypted = cryptoService.decryptWithSession(packet, keyStoreService.local().kemPublicKey().owner(), sender.owner(),
                            Base64Url.decode(session.secret()), session.sessionId(), session.nextReceiveSequence());
                    sessionMessage = parseSessionMessage(decrypted);
                    plaintext = sessionMessage.message();
                }
                default -> throw new IllegalStateException("Unsupported packet type: " + packet.type());
            }

            validateFreshness(packet);
            if (exchange != null) {
                boolean established = sessionHandshakeService.complete(packet, exchange, sender, keyStoreService.local(),
                        config.enableCompression, config.aeadAlgorithm, packetSender);
                decryptionHistoryService.recordSuccess(packet.sender());
                report(reassemblyId, packet.sender(), received, total, TransferProgressTracker.Status.COMPLETE);
                if (established) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.session_accepted", packet.sender()));
                }
                return;
            }
            if (!decryptionHistoryService.recordAcceptedPacket(packet.sender(), packet.messageId(), packet.nonce())) {
                throw new IllegalStateException("Replay or repeated nonce detected for " + packet.sender());
            }
            if (sessionMessage != null) {
                sessionService.recordReceivedMessage(packet.sender(), packet.sessionId(),
                        packet.sequence(), plaintext.getBytes(StandardCharsets.UTF_8).length);
            }
            decryptionHistoryService.recordSuccess(packet.sender());
            String signatureStatus = packet.signed()
                    ? ClientMessages.tr("text.krypt04mcg.signature.valid") + " / "
                    + ClientMessages.tr("text.krypt04mcg.trust." + trustState.name())
                    : ClientMessages.tr(packet.type() == PacketType.SESSION_MESSAGE
                            ? "text.krypt04mcg.signature.session"
                            : "text.krypt04mcg.signature.unsigned");
            decryptedMessageSink.accept(packet.sender(), plaintext);
            report(reassemblyId, packet.sender(), received, total, TransferProgressTracker.Status.COMPLETE);
            system.accept(ClientMessages.tr("text.krypt04mcg.decrypt_display", packet.sender(),
                    signatureStatus, plaintext));
        } catch (Exception e) {
            if (reassemblyId != null && total > 0) {
                var counts = reassembler.progress(reassemblyId);
                if (counts.isPresent()) {
                    // A conflicting fragment must not turn the admitted transfer into a failure.
                    report(reassemblyId, displaySender, counts.get().received(), counts.get().total(),
                            TransferProgressTracker.Status.TRANSFERRING);
                } else {
                    report(reassemblyId, displaySender, total, total, TransferProgressTracker.Status.FAILED);
                }
            }
            system.accept(ClientMessages.tr("text.krypt04mcg.decrypt_invalid", displaySender, e.getMessage()));
        }
    }

    /**
     * Parses session message for the authenticated chat receive handler.
     *
     * @param plaintext the plaintext bytes to encrypt or process
     * @return the result described above
     */
    private SessionMessagePayload parseSessionMessage(String plaintext) {
        SessionMessagePayload payload = gson.fromJson(plaintext, SessionMessagePayload.class);
        if (payload == null || payload.version() != SessionMessagePayload.VERSION || payload.message() == null) {
            throw new IllegalArgumentException("Session message payload is invalid");
        }
        return payload;
    }

    /**
     * Requires an authenticated timestamp layout and checks the configured bounded past/future acceptance
     * window. A valid signature or AEAD tag on an old packet is insufficient; durable replay checks are
     * still required independently.
     *
     * @param packet the packet being serialized, authenticated or processed
     */
    private void validateFreshness(EncryptedPacket packet) {
        if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION && !packet.signed()) {
            throw new IllegalArgumentException("Legacy unsigned packets have no authenticated timestamp");
        }
        long now = Instant.now().toEpochMilli();
        long maxAgeSeconds = Math.min(3_600, Math.max(30, config.maxPacketAgeSeconds));
        long maxFutureSeconds = Math.min(300, Math.max(0, config.maxFutureSkewSeconds));
        long oldest = now - maxAgeSeconds * 1_000L;
        long newest = now + maxFutureSeconds * 1_000L;
        if (packet.timestampMillis() < oldest || packet.timestampMillis() > newest) {
            throw new IllegalArgumentException("Packet timestamp is outside the accepted window");
        }
    }

    /**
     * Checks packet sender claims against the server/transport-provided source when available. Unbound
     * input requires a supported authenticated packet form; displayed player names alone are not transport
     * identity.
     *
     * @param transportSender the source identity supplied by the transport, not the unauthenticated body
     * @param packet the packet being serialized, authenticated or processed
     */
    private static void requireTransportIdentity(String transportSender, EncryptedPacket packet) {
        if (transportSender == null || transportSender.isBlank()) {
            if (!packet.signed() && packet.type() != dev.krypt04mcg.model.PacketType.SESSION_MESSAGE) {
                throw new IllegalArgumentException("Unsigned packet has no authenticated transport sender");
            }
            return;
        }
        if (!transportSender.equalsIgnoreCase(packet.sender())) {
            throw new IllegalArgumentException("Packet sender does not match the Minecraft transport sender");
        }
    }

    /**
     * Normalizes transport sender into the comparison/storage form used by the authenticated chat receive
     * handler.
     *
     * @param sender the sender or source associated with this operation
     * @return the result described above
     */
    private static String normalizeTransportSender(String sender) {
        return sender == null || sender.isBlank() ? "signed-unbound" : sender.toLowerCase(Locale.ROOT);
    }

    /**
     * Performs the extract fragment line operation for the authenticated chat receive handler.
     *
     * @param raw the raw supplied to this operation
     * @return the result described above
     */
    private Optional<String> extractFragmentLine(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String prefix = config.packetPrefix == null ? FragmentService.PREFIX : config.packetPrefix;
        String fragment = fragmentService.findFragment(raw, prefix);
        if (fragment == null || !fragmentService.isFragment(fragment, prefix)) {
            return Optional.empty();
        }
        if (config.receiveRegexMode) {
            try {
                if (config.receiveRegex == null || !Pattern.compile(config.receiveRegex).matcher(fragment).matches()) {
                    return Optional.empty();
                }
            } catch (java.util.regex.PatternSyntaxException e) {
                return Optional.empty();
            }
        }
        return Optional.of(fragment);
    }
}
