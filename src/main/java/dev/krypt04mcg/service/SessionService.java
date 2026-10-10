package dev.krypt04mcg.service;

import com.google.gson.Gson;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.SessionExchangePayload;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public final class SessionService {
    private final Path sessionsDir;
    private final SecureRandom random = new SecureRandom();
    private final Gson gson = JsonSupport.prettyGson();
    private final SensitiveFileStore sensitiveFiles;
    private final DecryptionHistoryService exchangeHistory;
    private final LedgerWriter ledgerWriter;

    /**
     * Creates a session service with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public SessionService(Path root) {
        this(root, null);
    }

    /**
     * Creates a session service with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     * @param ledgerWriter the ledger writer supplied to this operation
     */
    SessionService(Path root, LedgerWriter ledgerWriter) {
        this.sessionsDir = root.resolve("sessions");
        this.sensitiveFiles = new SensitiveFileStore(root);
        this.exchangeHistory = new DecryptionHistoryService(root);
        this.ledgerWriter = ledgerWriter == null ? sensitiveFiles::writeDurableString : ledgerWriter;
    }

    /**
     * Performs the migrate legacy files operation for the durable session state.
     *
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void migrateLegacyFiles() throws IOException {
        if (!Files.isDirectory(sessionsDir)) {
            return;
        }
        try (var stream = Files.list(sessionsDir)) {
            for (Path path : stream.filter(candidate -> candidate.toString().endsWith(".json")).toList()) {
                if (!SensitiveFileStore.isEncrypted(path)) {
                    State state = readState(path);
                    writeState(path, state);
                }
            }
        }
    }

    /**
     * Returns the recorded record for the durable session state.
     *
     * @param peer the peer identifier associated with this operation
     * @param peerFingerprint the peer fingerprint supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public SessionRecord createLocalSession(String peer, String peerFingerprint) throws IOException {
        SessionRecord record = newSession(peer, peerFingerprint);
        save(record);
        return record;
    }

    /**
     * Performs the new session operation for the durable session state.
     *
     * @param peer the peer identifier associated with this operation
     * @param peerFingerprint the peer fingerprint supplied to this operation
     * @return the result described above
     */
    public SessionRecord newSession(String peer, String peerFingerprint) {
        byte[] id = new byte[16];
        /*
         * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
         * Production randomness must remain unpredictable; a random nonce still depends on avoiding
         * collisions/reuse under its key.
         */
        random.nextBytes(id);
        try {
            return newSession(peer, peerFingerprint, Base64Url.encode(id));
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(id, (byte) 0);
        }
    }

    /**
     * Performs the new session operation for the durable session state.
     *
     * @param peer the peer identifier associated with this operation
     * @param peerFingerprint the peer fingerprint supplied to this operation
     * @param sessionId the identifier of the expected session epoch
     * @return the result described above
     */
    public SessionRecord newSession(String peer, String peerFingerprint, String sessionId) {
        byte[] secret = new byte[32];
        /*
         * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
         * Production randomness must remain unpredictable; a random nonce still depends on avoiding
         * collisions/reuse under its key.
         */
        random.nextBytes(secret);
        try {
            return new SessionRecord(peer, peerFingerprint, sessionId, Instant.now(), Instant.now(),
                    Base64Url.encode(secret), 0, 0L, 0L, 0L);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(secret, (byte) 0);
        }
    }

    /**
     * Returns the recorded record for the durable session state.
     *
     * @param peer the peer identifier associated with this operation
     * @param peerFingerprint the peer fingerprint supplied to this operation
     * @param sessionId the identifier of the expected session epoch
     * @param secret the shared secret used as key-derivation input
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public SessionRecord acceptRemoteSession(String peer, String peerFingerprint, String sessionId, String secret)
            throws IOException {
        SessionRecord record = new SessionRecord(peer, peerFingerprint, sessionId, Instant.now(), Instant.now(),
                secret, 0, 0L, 0L, 0L);
        save(record);
        return record;
    }

    /**
     * Looks up the requested entry in the durable session state without creating a replacement.
     *
     * @param peer the peer identifier associated with this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized Optional<SessionRecord> find(String peer) throws IOException {
        Path path = pathFor(peer);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        State state = readState(path);
        // Delivery may have happened before a crash or an IOException. Never use
        // the predecessor's keys while the peer might already use the candidate.
        if (state.prepared != null && state.session != null) {
            throw new IOException("Session switch awaits handshake retry for " + peer);
        }
        if (!SensitiveFileStore.isEncrypted(path)) {
            writeState(path, state);
        }
        return Optional.ofNullable(state.session);
    }

    /**
     * Performs the save operation for the durable session state.
     *
     * @param record the record supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void save(SessionRecord record) throws IOException {
        validate(record);
        Path path = pathFor(record.peer());
        State state = readState(path);
        if (state.prepared != null) throw new IOException("Unresolved session switch");
        state.session = record;
        state.epochId = record.sessionId();
        writeState(path, state);
    }

    /**
     * Performs the list operation for the durable session state.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized List<SessionRecord> list() throws IOException {
        if (!Files.exists(sessionsDir)) {
            return List.of();
        }
        try (var stream = Files.list(sessionsDir)) {
            return stream.filter(path -> path.toString().endsWith(".json"))
                    .map(path -> {
                        try {
                            State state = readState(path);
                            if (state.prepared != null) throw new IOException("Unresolved session switch");
                            if (!SensitiveFileStore.isEncrypted(path)) writeState(path, state);
                            return state.session;
                        } catch (IOException e) {
                            throw new IllegalStateException("Unable to read session " + path, e);
                        }
                    })
                    .filter(java.util.Objects::nonNull).toList();
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof IOException ioException) {
                throw ioException;
            }
            throw e;
        }
    }

    /**
     * Clears retained state in the durable session state.
     *
     * @param peer the peer identifier associated with this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void clear(String peer) throws IOException {
        Path path = pathFor(peer);
        State state = readState(path);
        if (state.prepared != null) throw new IOException("Retry the unresolved handshake before clearing");
        state.session = null;
        // Clearing a key must not clear the epoch or permit replay of old requests.
        writeState(path, state);
    }

    /**
     * Durably advances the outgoing request epoch and returns the current predecessor session ID before a
     * request can be sent. Reserving an epoch first prevents retry/restart behavior from silently reusing
     * a previously consumed handshake generation.
     *
     * @param peer the peer identifier associated with this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized OutgoingEpoch reserveHandshake(String peer) throws IOException {
        Path path = pathFor(peer);
        State state = readState(path);
        if (state.issuedEpoch == Long.MAX_VALUE) throw new IOException("Handshake epoch exhausted");
        state.issuedEpoch++;
        String previous = state.epochId;
        if (state.prepared != null) {
            // Delivery has only two possible outcomes. Try the candidate first,
            // then the predecessor on a fresh attempt if the peer never installed it.
            state.recoveryAttempts++;
            previous = (state.recoveryAttempts & 1) != 0 ? state.prepared.session().sessionId()
                    : state.prepared.previousSessionId();
        }
        writeState(path, state);
        return new OutgoingEpoch(previous, state.issuedEpoch);
    }

    /**
     * Checks the signed request against durable predecessor, request-epoch and replay state, returning an
     * already prepared matching response when recovery permits. Replayed, stale or conflicting requests
     * fail without replacing the active session.
     *
     * @param peer the peer identifier associated with this operation
     * @param payload the payload supplied to this operation
     * @param packet the packet being serialized, authenticated or processed
     * @param localFingerprint the local fingerprint supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized PreparedExchange checkRequest(String peer, SessionExchangePayload payload,
                                                       EncryptedPacket packet, String localFingerprint) throws IOException {
        State state = readState(pathFor(peer));
        requireFreshExchange(peer, packet, state);
        if (state.prepared != null && state.prepared.messageId().equals(Hex.encode(packet.messageId()))) {
            PreparedExchange prepared = state.prepared;
            if (!prepared.nonce().equals(Hex.encode(packet.nonce()))
                    || !prepared.requestDigest().equals(exchangeDigest(packet))
                    || !prepared.session().sessionId().equals(payload.sessionId())
                    || !prepared.session().peerFingerprint().equals(payload.initiatorFingerprint())
                    || !prepared.session().localFingerprint().equals(localFingerprint)
                    || prepared.requestEpoch() != payload.requestEpoch()
                    || !prepared.previousSessionId().equals(payload.previousSessionId())) {
                throw new IOException("Prepared exchange transcript changed");
            }
            return prepared;
        }
        if (state.prepared != null && payload.previousSessionId().equals(state.prepared.session().sessionId())) {
            // A signed successor proves that the initiator accepted our saved response.
            // Evaluate recovery in memory; invalid requests must never commit it.
            applyPrepared(state);
            requireReplayCapacity(state);
        }
        long accepted = state.remoteEpoch;
        if (state.prepared != null) {
            accepted = Math.max(accepted, state.prepared.requestEpoch());
        }
        if (payload.requestEpoch() <= accepted) throw new IOException("Stale session request epoch");
        // The peer can lose a response or restart before installing it. A strictly
        // newer request from the SAME initiator may replace that unconfirmed result.
        // This exception never applies to a session installed from our own request.
        boolean retryAfterLostResponse = state.epochId.equals(state.remoteSessionId)
                && state.remoteParent.equals(payload.previousSessionId());
        if (!retryAfterLostResponse) requirePredecessor(state, payload.previousSessionId(), payload.sessionId());
        if (state.epochId.equals(payload.sessionId())) throw new IOException("Session epoch already established");
        return null;
    }

    /**
     * Persists the candidate session and exact response with request identity, nonce and digest before
     * transmission. This journal supports recovery/retry of the same request while preventing a different
     * packet from borrowing a prepared response.
     *
     * @param peer the peer identifier associated with this operation
     * @param prepared the prepared supplied to this operation
     * @param payload the payload supplied to this operation
     * @param request the request supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void prepareExchange(String peer, PreparedExchange prepared,
                                               SessionExchangePayload payload, EncryptedPacket request) throws IOException {
        validate(prepared.session());
        if (checkRequest(peer, payload, request, prepared.session().localFingerprint()) != null) {
            throw new IOException("Exchange was concurrently prepared");
        }
        State state = readState(pathFor(peer));
        if (state.prepared != null && payload.previousSessionId().equals(state.prepared.session().sessionId())) {
            applyPrepared(state);
        }
        state.prepared = prepared;
        state.recoveryAttempts = 0;
        writeState(pathFor(peer), state);
    }

    /**
     * Commits only the prepared response correlated with the supplied request message ID. Session epoch
     * and replay records are persisted together; a mismatched or absent prepared exchange is not treated
     * as success.
     *
     * @param peer the peer identifier associated with this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void commitPrepared(String peer, String messageId) throws IOException {
        Path path = pathFor(peer);
        State state = readState(path);
        PreparedExchange prepared = state.prepared;
        if (prepared == null || !prepared.messageId().equals(messageId)) throw new IOException("Prepared exchange changed");
        applyPrepared(state);
        writeState(path, state);
    }

    /**
     * Performs the apply prepared operation for the durable session state.
     *
     * @param state the state supplied to this operation
     */
    private static void applyPrepared(State state) {
        PreparedExchange prepared = state.prepared;
        state.session = prepared.session();
        state.epochId = prepared.session().sessionId();
        state.remoteEpoch = prepared.requestEpoch();
        state.remoteSessionId = prepared.session().sessionId();
        state.remoteParent = prepared.previousSessionId();
        addReplay(state, prepared.messageId(), prepared.nonce());
        state.prepared = null;
        state.recoveryAttempts = 0;
    }

    /**
     * Validates the predecessor and response replay state before durably committing the received session.
     * The expected prior epoch prevents delayed valid responses from rolling an already replaced session
     * backward.
     *
     * @param session the session supplied to this operation
     * @param packet the packet being serialized, authenticated or processed
     * @param previousSessionId the previous session id supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void commitResponse(SessionRecord session, EncryptedPacket packet,
                                             String previousSessionId) throws IOException {
        validate(session);
        Path path = pathFor(session.peer());
        State state = readState(path);
        requireFreshExchange(session.peer(), packet, state);
        boolean recoveredPredecessor = state.prepared != null
                && previousSessionId.equals(state.prepared.previousSessionId());
        if (state.prepared != null && previousSessionId.equals(state.prepared.session().sessionId())) {
            // The response proves that the peer knew our durable candidate.
            // Recover it and install the successor in the same replacement.
            applyPrepared(state);
            requireReplayCapacity(state);
        }
        if (!recoveredPredecessor) requirePredecessor(state, previousSessionId, session.sessionId());
        if (state.epochId.equals(session.sessionId())) throw new IOException("Session epoch already established");
        state.session = session;
        state.epochId = session.sessionId();
        // Successful completion of our competing request supersedes an unsent response.
        state.prepared = null;
        state.recoveryAttempts = 0;
        addReplay(state, Hex.encode(packet.messageId()), Hex.encode(packet.nonce()));
        writeState(path, state);
    }

    /**
     * Rejects message-ID or nonce replays across current state, prepared exchanges and historical records,
     * then checks replay-cache capacity. Replay records are admission evidence, not a replacement for
     * cryptographic signature or freshness checks.
     *
     * @param peer the peer identifier associated with this operation
     * @param packet the packet being serialized, authenticated or processed
     * @param state the state supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void requireFreshExchange(String peer, EncryptedPacket packet, State state) throws IOException {
        pruneReplay(state);
        if (state.replay.containsKey("packet:" + Hex.encode(packet.messageId()))
                || state.replay.containsKey("nonce:" + Hex.encode(packet.nonce()))
                || state.prepared != null && state.prepared.nonce().equals(Hex.encode(packet.nonce()))
                    && !state.prepared.messageId().equals(Hex.encode(packet.messageId()))
                || exchangeHistory.wasAcceptedPacket(peer, packet.messageId(), packet.nonce())) {
            throw new IOException("Replay or repeated exchange nonce");
        }
        requireReplayCapacity(state);
    }

    /**
     * Refuses new exchange replay entries when bounded history is full instead of evicting still-live
     * evidence that could allow replay acceptance.
     *
     * @param state the state supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void requireReplayCapacity(State state) throws IOException {
        if (state.replay.size() > 32_768 - 2) throw new IOException("Exchange replay history full");
    }

    /**
     * Requires the expected previous session epoch to match durable state and forbids selecting the
     * already active epoch as the replacement.
     *
     * @param state the state supplied to this operation
     * @param previous the previous supplied to this operation
     * @param next the next supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void requirePredecessor(State state, String previous, String next) throws IOException {
        if (!state.epochId.equals(previous) || state.epochId.equals(next)) {
            throw new IOException("Session request predecessor changed");
        }
    }

    /**
     * Performs the prune replay operation for the durable session state.
     *
     * @param state the state supplied to this operation
     */
    private static void pruneReplay(State state) {
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(65));
        state.replay.values().removeIf(time -> time.isBefore(cutoff));
    }

    /**
     * Performs the add replay operation for the durable session state.
     *
     * @param state the state supplied to this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param nonce the nonce associated with this cryptographic operation
     */
    private static void addReplay(State state, String messageId, String nonce) {
        pruneReplay(state);
        state.replay.put("packet:" + messageId, Instant.now());
        state.replay.put("nonce:" + nonce, Instant.now());
    }

    /**
     * Hashes the canonical encoded exchange packet with SHA-256 for durable request correlation. The
     * digest detects conflicting encodings; authenticity still depends on the signed exchange validation
     * path.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    static String exchangeDigest(EncryptedPacket packet) throws IOException {
        try {
            /*
             * Delegates the requested digest to JCA for canonical fingerprint or context binding. A plain digest
             * is not a MAC or signature and cannot independently establish trust, freshness or secrecy of
             * low-entropy input.
             */
            return Hex.encode(java.security.MessageDigest.getInstance("SHA-256").digest(new PacketCodec().encode(packet)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Requires the exact expected chat-send sequence before persisting the incremented counter and usage
     * totals. Persistence associates counters with the current session identity/epoch rather than allowing
     * silent reuse after a failed state transition.
     *
     * @param peer the peer identifier associated with this operation
     * @param expectedSequence the expected sequence supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void recordSentMessage(String peer, long expectedSequence, long bytes) throws IOException {
        SessionRecord session = find(peer)
                .orElseThrow(() -> new IOException("No active session for " + peer));
        if (session.nextSendSequence() != expectedSequence) {
            throw new IOException("Session send sequence changed for " + peer);
        }
        save(new SessionRecord(session.peer(), session.peerFingerprint(), session.sessionId(), session.createdAt(),
                Instant.now(), session.secret(), session.messageCount() + 1, session.bytesUsed() + Math.max(0, bytes),
                expectedSequence + 1, session.nextReceiveSequence(), session.localFingerprint(),
                session.nextApiSendSequence(), session.nextApiReceiveSequence(), session.nextApiControlSendSequence(),
                session.nextApiControlReceiveSequence()));
    }

    /**
     * Requires the active session ID and exact next receive sequence before durably recording acceptance
     * and usage. Rejecting gaps/repeats is separate from the AEAD tag check and prevents accepted records
     * from replaying within the epoch.
     *
     * @param peer the peer identifier associated with this operation
     * @param sessionId the identifier of the expected session epoch
     * @param sequence the record or control sequence in the relevant replay domain
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void recordReceivedMessage(String peer, String sessionId, long sequence, long bytes)
            throws IOException {
        SessionRecord session = find(peer)
                .orElseThrow(() -> new IOException("No active session for " + peer));
        if (!session.sessionId().equals(sessionId) || session.nextReceiveSequence() != sequence) {
            throw new IOException("Session epoch or receive sequence mismatch for " + peer);
        }
        save(new SessionRecord(session.peer(), session.peerFingerprint(), session.sessionId(), session.createdAt(),
                Instant.now(), session.secret(), session.messageCount() + 1, session.bytesUsed() + Math.max(0, bytes),
                session.nextSendSequence(), sequence + 1, session.localFingerprint(),
                session.nextApiSendSequence(), session.nextApiReceiveSequence(), session.nextApiControlSendSequence(),
                session.nextApiControlReceiveSequence()));
    }

    /**
     * Durably reserves the next API send position for the expected session epoch, keeping control and data
     * counters separate. The wire value encodes parity (odd control, even data) and rejects exhaustion
     * before doubling. The caller must not reuse an old reservation after the epoch changes.
     *
     * @param peer the peer identifier associated with this operation
     * @param sessionId the identifier of the expected session epoch
     * @param control the control supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized long reserveApiSend(String peer, String sessionId, boolean control, long bytes) throws IOException {
        SessionRecord session = requireEpoch(peer, sessionId);
        long next = control ? session.nextApiControlSendSequence() : session.nextApiSendSequence();
        if (next >= (Long.MAX_VALUE - 1) / 2) throw new IOException("API sequence exhausted");
        saveApiCounters(session, control ? session.nextApiSendSequence() : next + 1, session.nextApiReceiveSequence(),
                control ? next + 1 : session.nextApiControlSendSequence(), session.nextApiControlReceiveSequence(), control, bytes);
        return next * 2 + (control ? 1 : 0);
    }

    /**
     * Validates the session epoch, nonnegative usable sequence and data/control parity, and requires the
     * received sequence not to precede the stored next counter. This API path permits forward gaps but
     * rejects repeated or lower sequences. It durably advances the matching counter to one past the
     * accepted position; control and data use separate replay domains.
     *
     * @param peer the peer identifier associated with this operation
     * @param sessionId the identifier of the expected session epoch
     * @param sequence the record or control sequence in the relevant replay domain
     * @param control the control supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void recordApiReceived(String peer, String sessionId, long sequence, boolean control, long bytes) throws IOException {
        SessionRecord session = requireEpoch(peer, sessionId);
        long next = control ? session.nextApiControlReceiveSequence() : session.nextApiReceiveSequence();
        if (sequence < 0 || sequence == Long.MAX_VALUE || (sequence & 1) != (control ? 1 : 0) || sequence / 2 < next)
            throw new IOException("Repeated or invalid API sequence");
        saveApiCounters(session, session.nextApiSendSequence(), control ? session.nextApiReceiveSequence() : sequence / 2 + 1,
                session.nextApiControlSendSequence(), control ? sequence / 2 + 1 : session.nextApiControlReceiveSequence(), control, bytes);
    }

    /**
     * Checks the epoch required by the durable session state and rejects invalid state instead of
     * continuing.
     *
     * @param peer the peer identifier associated with this operation
     * @param id the id supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private SessionRecord requireEpoch(String peer, String id) throws IOException {
        SessionRecord session = find(peer).orElseThrow(() -> new IOException("Missing session"));
        if (!session.sessionId().equals(id)) throw new IOException("Session changed");
        return session;
    }

    /**
     * Performs the save api counters operation for the durable session state.
     *
     * @param s the s supplied to this operation
     * @param send the send supplied to this operation
     * @param receive the receive supplied to this operation
     * @param controlSend the control send supplied to this operation
     * @param controlReceive the control receive supplied to this operation
     * @param control the control supplied to this operation
     * @param bytes the bytes supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void saveApiCounters(SessionRecord s, long send, long receive, long controlSend, long controlReceive,
                                  boolean control, long bytes) throws IOException {
        save(new SessionRecord(s.peer(), s.peerFingerprint(), s.sessionId(), s.createdAt(), Instant.now(), s.secret(),
                control ? s.messageCount() : Math.addExact(s.messageCount(), 1),
                control ? s.bytesUsed() : Math.addExact(s.bytesUsed(), Math.max(0, bytes)),
                s.nextSendSequence(), s.nextReceiveSequence(), s.localFingerprint(), send, receive, controlSend, controlReceive));
    }

    /**
     * Evaluates session lifetime, message-count and byte-use rotation thresholds from stored metadata.
     * Expiry policy is separate from cryptographic verification and does not itself destroy all copies of
     * session secrets.
     *
     * @param session the session supplied to this operation
     * @param ttlMinutes the ttl minutes supplied to this operation
     * @param maxMessages the max messages supplied to this operation
     * @param rotateAfterBytes the rotate after bytes supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean isExpired(SessionRecord session, int ttlMinutes, int maxMessages, long rotateAfterBytes) {
        Instant expiresAt = session.createdAt().plus(Duration.ofMinutes(ttlMinutes));
        return Instant.now().isAfter(expiresAt)
                || session.messageCount() >= maxMessages
                || session.bytesUsed() >= rotateAfterBytes;
    }

    /**
     * Performs the path for operation for the durable session state.
     *
     * @param peer the peer identifier associated with this operation
     * @return the result described above
     */
    private Path pathFor(String peer) {
        return sessionsDir.resolve(peer.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", "_") + ".json");
    }

    /**
     * Reads state from the input used by the durable session state.
     *
     * @param path the filesystem path used by this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private State readState(Path path) throws IOException {
        if (!Files.exists(path)) return new State();
        try {
            var json = com.google.gson.JsonParser.parseString(sensitiveFiles.readString(path)).getAsJsonObject();
            State state;
            if (json.has("stateVersion")) {
                state = gson.fromJson(json, State.class);
                if (state.stateVersion != 1 || state.epochId == null
                        || state.remoteSessionId == null || state.remoteParent == null
                        || state.replay == null || state.issuedEpoch < 0 || state.remoteEpoch < 0
                        || state.recoveryAttempts < 0) {
                    throw new IOException("Invalid session ledger");
                }
            } else {
                state = new State();
                state.session = gson.fromJson(json, SessionRecord.class);
                validate(state.session);
                state.epochId = state.session.sessionId();
            }
            if (state.session != null) validate(state.session);
            if (state.prepared != null) validate(state.prepared.session());
            return state;
        } catch (RuntimeException e) {
            throw new IOException("Invalid session ledger", e);
        }
    }

    /**
     * Writes state to the output used by the durable session state.
     *
     * @param path the filesystem path used by this operation
     * @param state the state supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void writeState(Path path, State state) throws IOException {
        ledgerWriter.write(path, gson.toJson(state));
    }

    @FunctionalInterface
    interface LedgerWriter {
        /**
         * Writes the supplied value to the output used by the durable session state.
         *
         * @param path the filesystem path used by this operation
         * @param value the value supplied to this operation
         * @throws IOException if input/output, stored-state validation or resource handling fails
         */
        void write(Path path, String value) throws IOException;
    }

    public record OutgoingEpoch(String previousSessionId, long requestEpoch) {}

    public record PreparedExchange(SessionRecord session, EncryptedPacket response, String messageId, String nonce,
                                   String previousSessionId, long requestEpoch, String requestDigest) {}

    private static final class State {
        int stateVersion = 1;
        SessionRecord session;
        String epochId = "";
        long issuedEpoch;
        long remoteEpoch;
        long recoveryAttempts;
        String remoteSessionId = "";
        String remoteParent = "";
        Map<String, Instant> replay = new HashMap<>();
        PreparedExchange prepared;
    }

    /**
     * Checks the input required by the durable session state and rejects invalid state instead of
     * continuing.
     *
     * @param record the record supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private static void validate(SessionRecord record) throws IOException {
        try {
            if (record == null || record.peer() == null || record.peer().isBlank()
                    || record.peerFingerprint() == null || record.peerFingerprint().isBlank()
                    || record.createdAt() == null || record.lastUsedAt() == null
                    || Base64Url.decode(record.sessionId()).length != 16
                    || Base64Url.decode(record.secret()).length != 32
                    || record.messageCount() < 0 || record.bytesUsed() < 0
                    || record.nextSendSequence() < 0 || record.nextReceiveSequence() < 0
                    || record.nextApiSendSequence() < 0 || record.nextApiReceiveSequence() < 0
                    || record.nextApiControlSendSequence() < 0 || record.nextApiControlReceiveSequence() < 0) {
                throw new IOException("Session record is invalid");
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("Session record contains invalid key material", e);
        }
    }
}
