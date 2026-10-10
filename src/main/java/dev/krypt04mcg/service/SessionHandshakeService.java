package dev.krypt04mcg.service;

import com.google.gson.Gson;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.crypto.EphemeralKemKeyPair;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionExchangePayload;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.util.JsonSupport;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class SessionHandshakeService implements AutoCloseable {
    private static final Duration PENDING_TTL = Duration.ofMinutes(5);
    private static final int MAX_PENDING = 64;
    private static final ScheduledExecutorService EXPIRY_EXECUTOR = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "Krypt04Mcg Ephemeral KEM Expiry");
        thread.setDaemon(true);
        return thread;
    });

    private final CryptoService cryptoService;
    private final SessionService sessionService;
    private final Gson gson = JsonSupport.prettyGson();
    private final Map<String, PendingHandshake> pending = new LinkedHashMap<>();

    /**
     * Creates a session handshake service with the supplied dependencies and initial state.
     *
     * @param cryptoService the crypto service supplied to this operation
     * @param sessionService the session service supplied to this operation
     */
    public SessionHandshakeService(CryptoService cryptoService, SessionService sessionService) {
        this.cryptoService = cryptoService;
        this.sessionService = sessionService;
    }

    /**
     * Reserves a durable predecessor/request epoch before generating an ephemeral KEM key and signed
     * request envelope. The pending entry binds peer identity, session ID and request message ID to the
     * ephemeral key, with bounded fixed expiry. Failure closes newly generated ephemeral material.
     *
     * @param receiver the intended recipient associated with this operation
     * @param senderKeys the local sender key material
     * @param ephemeralAlgorithm the ephemeral algorithm supplied to this operation
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public synchronized EncryptedPacket begin(PublicIdentity receiver, LocalKeyMaterial senderKeys,
                                              KemAlgorithm ephemeralAlgorithm, boolean compress,
                                              AeadAlgorithm aeadAlgorithm) throws CryptoException {
        cleanupExpired();
        SessionService.OutgoingEpoch epoch;
        try {
            epoch = sessionService.reserveHandshake(receiver.owner());
        } catch (IOException e) {
            throw new CryptoException("Unable to reserve durable handshake epoch", e);
        }
        String sender = senderKeys.kemPublicKey().owner();
        EphemeralKemKeyPair ephemeral = cryptoService.generateEphemeralKemKeyPair(ephemeralAlgorithm);
        try {
            byte[] sessionIdBytes = cryptoService.randomMessageId();
            String sessionId = Base64Url.encode(sessionIdBytes);
            Instant createdAt = Instant.now();
            KeyRecord ephemeralPublic = cryptoService.keyRecord(ephemeral.algorithm().identifier() + "/public",
                    sender, senderKeys.kemPublicKey().uuid(), createdAt, ephemeral.publicKey());
            SessionExchangePayload payload = new SessionExchangePayload(SessionExchangePayload.VERSION,
                    SessionExchangePayload.Kind.REQUEST, sender, senderKeys.kemPublicKey().uuid(), receiver.owner(),
                    receiver.uuid(), sessionId, "", fingerprint(senderKeys), fingerprint(receiver),
                    ephemeral.algorithm().identifier(), ephemeralPublic.keyData(), "", createdAt.toEpochMilli(),
                    epoch.previousSessionId(), epoch.requestEpoch());
            EncryptedPacket packet = cryptoService.encryptSessionExchange(receiver.kemPublicKey(), receiver.owner(),
                    senderKeys, sender, gson.toJson(payload), false, compress, aeadAlgorithm);
            putPending(receiver.owner(), new PendingHandshake(receiver, sessionId, Hex.encode(packet.messageId()),
                    ephemeral, createdAt, epoch.previousSessionId(), epoch.requestEpoch()));
            return packet;
        } catch (RuntimeException | CryptoException e) {
            ephemeral.close();
            throw e;
        }
    }

    /**
     * Requires a signed session-exchange envelope and uses the pending ephemeral key for a response or the
     * long-term key for a request. JSON is parsed only after cryptographic decryption. Parsing does not
     * complete the handshake; correlation, identity and durable epoch checks occur in complete.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param receiverKeys the local recipient key material
     * @param sender the sender or source associated with this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized DecryptedExchange decrypt(EncryptedPacket packet, LocalKeyMaterial receiverKeys,
                                                   PublicIdentity sender) throws CryptoException, IOException {
        cleanupExpired();
        requireSignedExchange(packet);
        String plaintext;
        if (isResponse(packet)) {
            PendingHandshake pendingHandshake = pending.get(normalize(packet.sender()));
            if (pendingHandshake == null) {
                throw new CryptoException("No pending ephemeral KEM exchange with " + packet.sender());
            }
            plaintext = cryptoService.decryptSessionExchangeResponse(packet,
                    receiverKeys.kemPublicKey().owner(), pendingHandshake.ephemeral(), sender);
        } else {
            plaintext = cryptoService.decrypt(packet, receiverKeys, sender);
        }
        try {
            SessionExchangePayload payload = gson.fromJson(plaintext, SessionExchangePayload.class);
            if (payload == null) {
                throw new IOException("Session exchange payload is empty");
            }
            return new DecryptedExchange(payload, plaintext);
        } catch (RuntimeException e) {
            throw new IOException("Session exchange payload is invalid", e);
        }
    }

    /**
     * Validates authenticated exchange fields against both identities and dispatches request/response
     * completion. Durable session preparation/commit and packet transmission are coordinated so a failed
     * send or save does not silently advance an unrelated epoch.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param exchange the exchange supplied to this operation
     * @param sender the sender or source associated with this operation
     * @param receiverKeys the local recipient key material
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @param packetSender the packet sender supplied to this operation
     * @return whether the condition or operation described above succeeds
     * @throws Exception if the delegated operation cannot complete successfully
     */
    public synchronized boolean complete(EncryptedPacket packet, DecryptedExchange exchange,
                                         PublicIdentity sender, LocalKeyMaterial receiverKeys,
                                         boolean compress, AeadAlgorithm aeadAlgorithm,
                                         PacketSender packetSender) throws Exception {
        cleanupExpired();
        SessionExchangePayload payload = exchange.payload();
        validateCommon(packet, payload, sender, receiverKeys);
        if (isResponse(packet)) {
            completeResponse(packet, payload, sender, receiverKeys);
            return true;
        } else {
            return completeRequest(packet, payload, sender, receiverKeys, compress, aeadAlgorithm, packetSender);
        }
    }

    /**
     * Checks request shape and predecessor epoch, reuses a durably prepared matching response when
     * retrying, and resolves simultaneous requests deterministically. A new session response is encrypted
     * to the validated ephemeral public key, journaled before sending and committed after submission.
     * Competing pending key material is discarded only after successful exchange processing.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param payload the payload supplied to this operation
     * @param sender the sender or source associated with this operation
     * @param receiverKeys the local recipient key material
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @param packetSender the packet sender supplied to this operation
     * @return whether the condition or operation described above succeeds
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private boolean completeRequest(EncryptedPacket packet, SessionExchangePayload payload, PublicIdentity sender,
                                    LocalKeyMaterial receiverKeys, boolean compress, AeadAlgorithm aeadAlgorithm,
                                    PacketSender packetSender) throws Exception {
        if (payload.kind() != SessionExchangePayload.Kind.REQUEST || !payload.requestMessageId().isEmpty()
                || !payload.sessionSecret().isEmpty()) {
            throw new IOException("Invalid session exchange request fields");
        }
        if (Base64Url.decode(payload.sessionId()).length != CryptoService.MESSAGE_ID_BYTES) {
            throw new IOException("Invalid session exchange ID");
        }
        var prepared = sessionService.checkRequest(sender.owner(), payload, packet, fingerprint(receiverKeys));
        if (prepared != null) {
            packetSender.send(prepared.response(), sender.owner());
            sessionService.commitPrepared(sender.owner(), prepared.messageId());
            discardPending(sender.owner());
            return true;
        }
        PendingHandshake simultaneous = pending.get(normalize(sender.owner()));
        if (simultaneous != null) {
            if (receiverKeys.kemPublicKey().owner().compareToIgnoreCase(sender.owner()) < 0) {
                return false;
            }
        }
        KemAlgorithm.fromIdentifier(payload.ephemeralKem());
        KeyRecord ephemeralPublic = cryptoService.validateEphemeralKemPublicKey(payload.ephemeralKem(),
                payload.initiator(), payload.initiatorUuid(), payload.ephemeralPublicKey(),
                Instant.ofEpochMilli(payload.createdAtMillis()));
        SessionRecord session = sessionService.newSession(sender.owner(), fingerprint(sender), payload.sessionId())
                .withLocalFingerprint(fingerprint(receiverKeys));
        SessionExchangePayload response = new SessionExchangePayload(SessionExchangePayload.VERSION,
                SessionExchangePayload.Kind.RESPONSE, payload.initiator(), payload.initiatorUuid(),
                payload.responder(), payload.responderUuid(), session.sessionId(), Hex.encode(packet.messageId()),
                payload.initiatorFingerprint(), payload.responderFingerprint(), payload.ephemeralKem(), "",
                session.secret(), System.currentTimeMillis(), payload.previousSessionId(), payload.requestEpoch());
        EncryptedPacket responsePacket = cryptoService.encryptSessionExchange(ephemeralPublic, sender.owner(),
                receiverKeys, receiverKeys.kemPublicKey().owner(), gson.toJson(response), true, compress, aeadAlgorithm);
        sessionService.prepareExchange(sender.owner(), new SessionService.PreparedExchange(session, responsePacket,
                Hex.encode(packet.messageId()), Hex.encode(packet.nonce()), payload.previousSessionId(), payload.requestEpoch(),
                SessionService.exchangeDigest(packet)), payload, packet);
        packetSender.send(responsePacket, sender.owner());
        sessionService.commitPrepared(sender.owner(), Hex.encode(packet.messageId()));
        // Keep the previous response key until the competing exchange has succeeded.
        // Invalid key material or a failed send/save must not destroy the pending exchange.
        if (simultaneous != null && pending.remove(normalize(sender.owner()), simultaneous)) {
            simultaneous.ephemeral().close();
        }
        return true;
    }

    /**
     * Requires exact pending request, peer UUID, session ID, ephemeral suite, predecessor and epoch
     * correlation plus a 32-byte session secret. The new session is durably committed before the pending
     * ephemeral key is removed and closed, preserving recoverability if persistence fails.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param payload the payload supplied to this operation
     * @param sender the sender or source associated with this operation
     * @param receiverKeys the local recipient key material
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void completeResponse(EncryptedPacket packet, SessionExchangePayload payload, PublicIdentity sender, LocalKeyMaterial receiverKeys)
            throws IOException {
        PendingHandshake pendingHandshake = pending.get(normalize(sender.owner()));
        if (pendingHandshake == null || payload.kind() != SessionExchangePayload.Kind.RESPONSE
                || !pendingHandshake.sessionId().equals(payload.sessionId())
                || !pendingHandshake.requestMessageId().equalsIgnoreCase(payload.requestMessageId())
                || !pendingHandshake.peer().uuid().equalsIgnoreCase(payload.responderUuid())
                || !payload.ephemeralPublicKey().isEmpty()
                || !pendingHandshake.ephemeral().algorithm().identifier().equalsIgnoreCase(payload.ephemeralKem())
                || !pendingHandshake.previousSessionId().equals(payload.previousSessionId())
                || pendingHandshake.requestEpoch() != payload.requestEpoch()
                || Base64Url.decode(payload.sessionSecret()).length != 32) {
            throw new IOException("Session exchange response does not match the pending request");
        }
        sessionService.commitResponse(new SessionRecord(sender.owner(), fingerprint(sender), payload.sessionId(), Instant.now(), Instant.now(),
                payload.sessionSecret(), 0, 0L).withLocalFingerprint(fingerprint(receiverKeys)), packet, payload.previousSessionId());
        pending.remove(normalize(sender.owner()));
        pendingHandshake.ephemeral().close();
    }

    /**
     * Validates version, time window, initiator/responder names and UUIDs, both fingerprints and
     * predecessor/epoch fields against authenticated packet context. These checks prevent an otherwise
     * valid signed envelope from being attached to a different pending identity or epoch.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param payload the payload supplied to this operation
     * @param sender the sender or source associated with this operation
     * @param receiverKeys the local recipient key material
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void validateCommon(EncryptedPacket packet, SessionExchangePayload payload, PublicIdentity sender,
                                       LocalKeyMaterial receiverKeys) throws IOException {
        PublicIdentity receiver = new PublicIdentity(receiverKeys.kemPublicKey().owner(),
                receiverKeys.kemPublicKey().uuid(), receiverKeys.kemPublicKey(), receiverKeys.signaturePublicKey());
        long now = System.currentTimeMillis();
        if (payload.version() != SessionExchangePayload.VERSION
                || payload.requestEpoch() <= 0 || payload.previousSessionId() == null
                || !payload.previousSessionId().isEmpty()
                    && Base64Url.decode(payload.previousSessionId()).length != CryptoService.MESSAGE_ID_BYTES
                || packet.timestampMillis() < now - Duration.ofHours(1).toMillis()
                || packet.timestampMillis() > now + Duration.ofMinutes(5).toMillis()
                || !payload.initiator().equalsIgnoreCase(isResponse(packet) ? receiver.owner() : sender.owner())
                || !payload.responder().equalsIgnoreCase(isResponse(packet) ? sender.owner() : receiver.owner())
                || !payload.initiatorUuid().equalsIgnoreCase(isResponse(packet) ? receiver.uuid() : sender.uuid())
                || !payload.responderUuid().equalsIgnoreCase(isResponse(packet) ? sender.uuid() : receiver.uuid())
                || !payload.initiatorFingerprint().equalsIgnoreCase(
                isResponse(packet) ? fingerprint(receiver) : fingerprint(sender))
                || !payload.responderFingerprint().equalsIgnoreCase(
                isResponse(packet) ? fingerprint(sender) : fingerprint(receiver))
                || Math.abs(payload.createdAtMillis() - packet.timestampMillis()) > Duration.ofSeconds(5).toMillis()) {
            throw new IOException("Session exchange transcript identity mismatch");
        }
    }

    /**
     * Admits a bounded pending exchange and arranges fixed key expiry. Replacing a peer entry or reaching
     * capacity must release displaced ephemeral key material according to the implemented lifecycle.
     *
     * @param peer the peer identifier associated with this operation
     * @param value the value supplied to this operation
     */
    private void putPending(String peer, PendingHandshake value) {
        String normalized = normalize(peer);
        PendingHandshake replaced = pending.put(normalized, value);
        if (replaced != null) {
            replaced.ephemeral().close();
        }
        EXPIRY_EXECUTOR.schedule(() -> expire(normalized, value), PENDING_TTL.toMillis(), TimeUnit.MILLISECONDS);
        while (pending.size() > MAX_PENDING) {
            String oldest = pending.keySet().iterator().next();
            pending.remove(oldest).ephemeral().close();
        }
    }

    /**
     * Removes the peer pending handshake and closes its ephemeral key holder, preventing further response
     * decryption with that state.
     *
     * @param peer the peer identifier associated with this operation
     */
    private void discardPending(String peer) {
        PendingHandshake previous = pending.remove(normalize(peer));
        if (previous != null) previous.ephemeral().close();
    }

    /**
     * Expires only the scheduled pending exchange still matching its identity and deadline, then closes
     * ephemeral material. Late callbacks must not retire a replacement exchange.
     *
     * @param peer the peer identifier associated with this operation
     * @param expected the expected supplied to this operation
     */
    private synchronized void expire(String peer, PendingHandshake expected) {
        if (pending.get(peer) == expected) {
            pending.remove(peer);
            expected.ephemeral().close();
        }
    }

    /**
     * Removes expired pending exchanges based on their original creation times and closes their ephemeral
     * keys. Duplicate or continued traffic does not refresh the fixed lifetime.
     */
    private void cleanupExpired() {
        Instant cutoff = Instant.now().minus(PENDING_TTL);
        pending.entrySet().removeIf(entry -> {
            if (entry.getValue().createdAt().isBefore(cutoff)) {
                entry.getValue().ephemeral().close();
                return true;
            }
            return false;
        });
    }

    /**
     * Cancels pending handshake state for the specified peer and releases ephemeral key material.
     * Persisted active sessions are managed separately.
     *
     * @param peer the peer identifier associated with this operation
     * @param requestMessageId the request message id supplied to this operation
     */
    public synchronized void cancel(String peer, String requestMessageId) {
        PendingHandshake request = pending.get(normalize(peer));
        if (request != null && request.requestMessageId().equals(requestMessageId)) {
            pending.remove(normalize(peer));
            request.ephemeral().close();
        }
    }

    /**
     * Checks the signed exchange required by the session handshake state machine and rejects invalid state
     * instead of continuing.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static void requireSignedExchange(EncryptedPacket packet) throws CryptoException {
        if (packet.type() != PacketType.SESSION_EXCHANGE || !packet.signed()) {
            throw new CryptoException("Session exchange packets must use the signed SESSION_EXCHANGE type");
        }
    }

    /**
     * Reports whether response holds for the session handshake state machine.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @return whether the condition or operation described above succeeds
     */
    private static boolean isResponse(EncryptedPacket packet) {
        return (packet.flags() & CryptoService.FLAG_SESSION_RESPONSE) != 0;
    }

    /**
     * Returns the fingerprint value used by the session handshake state machine.
     *
     * @param material the material supplied to this operation
     * @return the result described above
     */
    private static String fingerprint(LocalKeyMaterial material) {
        return material.kemPublicKey().fingerprint() + ":" + material.signaturePublicKey().fingerprint();
    }

    /**
     * Returns the fingerprint value used by the session handshake state machine.
     *
     * @param identity the identity supplied to this operation
     * @return the result described above
     */
    private static String fingerprint(PublicIdentity identity) {
        return identity.kemPublicKey().fingerprint() + ":" + identity.signaturePublicKey().fingerprint();
    }

    /**
     * Normalizes the supplied identifier into the comparison/storage form used by the session handshake
     * state machine.
     *
     * @param player the player supplied to this operation
     * @return the result described above
     */
    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT);
    }

    /**
     * Closes all retained pending ephemeral key holders and clears pending state. This is handshake
     * cleanup rather than destruction of every persisted long-term or session key.
     */
    @Override
    public synchronized void close() {
        pending.values().forEach(value -> value.ephemeral().close());
        pending.clear();
    }

    public record DecryptedExchange(SessionExchangePayload payload, String plaintext) {
    }

    @FunctionalInterface
    public interface PacketSender {
        /**
         * Submits the supplied data through the session handshake state machine path. Local submission does
         * not by itself acknowledge remote receipt.
         *
         * @param packet the packet being serialized, authenticated or processed
         * @param receiver the intended recipient associated with this operation
         * @throws Exception if the delegated operation cannot complete successfully
         */
        void send(EncryptedPacket packet, String receiver) throws Exception;
    }

    private record PendingHandshake(PublicIdentity peer, String sessionId, String requestMessageId,
                                    EphemeralKemKeyPair ephemeral, Instant createdAt,
                                    String previousSessionId, long requestEpoch) {
    }
}
