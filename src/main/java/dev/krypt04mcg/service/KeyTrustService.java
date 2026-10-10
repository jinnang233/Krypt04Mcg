package dev.krypt04mcg.service;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class KeyTrustService {
    private final Path trustFile;
    private final Gson gson = JsonSupport.prettyGson();
    private final SensitiveFileStore sensitiveFiles;

    /**
     * Creates a key trust service with the supplied dependencies and initial state.
     *
     * @param root the account or configuration storage root
     */
    public KeyTrustService(Path root) {
        this.trustFile = root.resolve("keys").resolve("trust.json");
        this.sensitiveFiles = new SensitiveFileStore(root);
    }

    /**
     * Resolves persisted trust against both current public-key fingerprints. A changed fingerprint binding
     * yields distrust; legacy verified records without fingerprints are not silently promoted to verified
     * identity. TOFU is first-use continuity, not independent peer authentication.
     *
     * @param player the player supplied to this operation
     * @param identity the identity supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized TrustState trustState(String player, PublicIdentity identity) throws IOException {
        TrustBinding stored = readTrust().get(normalize(player));
        if (stored == null) {
            return identity == null ? TrustState.UNTRUSTED : TrustState.TOFU_TRUSTED;
        }
        if (identity != null && stored.hasFingerprints() && !stored.matches(identity)) {
            return TrustState.DISTRUSTED;
        }
        if (stored.state() == TrustState.VERIFIED && !stored.hasFingerprints()) {
            return identity == null ? TrustState.UNTRUSTED : TrustState.TOFU_TRUSTED;
        }
        return stored.state();
    }

    /**
     * Performs the mark tofu trusted operation for the public-key trust bindings.
     *
     * @param player the player supplied to this operation
     * @param identity the identity supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void markTofuTrusted(String player, PublicIdentity identity) throws IOException {
        setTrustState(player, TrustState.TOFU_TRUSTED, identity);
    }

    /**
     * Persists a first-use fingerprint binding only when no existing binding is present. Existing
     * verification/distrust decisions are preserved rather than overwritten by later imports.
     *
     * @param player the player supplied to this operation
     * @param identity the identity supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void rememberTofu(String player, PublicIdentity identity) throws IOException {
        Map<String, TrustBinding> trust = readTrust();
        if (trust.putIfAbsent(normalize(player), TrustBinding.of(TrustState.TOFU_TRUSTED, identity)) == null) {
            sensitiveFiles.writeString(trustFile, gson.toJson(trust));
        }
    }

    /**
     * Records explicit user verification bound to both public-key fingerprints and rejects missing
     * identity material. Verification here represents a trust decision supplied by the caller, not
     * automatic out-of-band identity proof.
     *
     * @param player the player supplied to this operation
     * @param identity the identity supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void markVerified(String player, PublicIdentity identity) throws IOException {
        if (identity == null) {
            throw new IOException("A verified trust record requires both public keys");
        }
        setTrustState(player, TrustState.VERIFIED, identity);
    }

    /**
     * Persists a distrust decision and its current identity binding so callers can reject sending or
     * accepting traffic associated with that identity.
     *
     * @param player the player supplied to this operation
     * @param identity the identity supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void markDistrusted(String player, PublicIdentity identity) throws IOException {
        setTrustState(player, TrustState.DISTRUSTED, identity);
    }

    /**
     * Performs the forget operation for the public-key trust bindings.
     *
     * @param player the player supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    public synchronized void forget(String player) throws IOException {
        Map<String, TrustBinding> trust = readTrust();
        if (trust.remove(normalize(player)) != null) {
            sensitiveFiles.writeString(trustFile, gson.toJson(trust));
        }
    }

    /**
     * Normalizes the complete fingerprint pair and compares UTF-8 bytes using MessageDigest.isEqual.
     * Matching identifies the recorded keys; it does not establish how the fingerprint was originally
     * trusted.
     *
     * @param identity the identity supplied to this operation
     * @param fingerprintPair the fingerprint pair supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean fingerprintMatches(PublicIdentity identity, String fingerprintPair) {
        if (identity == null || fingerprintPair == null) {
            return false;
        }
        String expected = fingerprintPair(identity).toLowerCase(Locale.ROOT);
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] suppliedBytes = fingerprintPair.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        /*
         * Compares digest/tag bytes with the JDK authentication-oriented byte comparison rather than
         * converting them to Strings. Equality still depends on the supplied key/context and does not replace
         * identity or replay checks.
         */
        return MessageDigest.isEqual(expectedBytes, suppliedBytes);
    }

    /**
     * Combines full KEM and signature public-key fingerprints in a fixed order for identity binding. Both
     * keys participate in trust continuity; one matching component alone is insufficient.
     *
     * @param identity the identity supplied to this operation
     * @return the result described above
     */
    public static String fingerprintPair(PublicIdentity identity) {
        return identity.kemPublicKey().fingerprint() + ":" + identity.signaturePublicKey().fingerprint();
    }

    /**
     * Updates the trust state used by the public-key trust bindings.
     *
     * @param player the player supplied to this operation
     * @param state the state supplied to this operation
     * @param identity the identity supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private void setTrustState(String player, TrustState state, PublicIdentity identity) throws IOException {
        Map<String, TrustBinding> trust = readTrust();
        trust.put(normalize(player), TrustBinding.of(state, identity));
        sensitiveFiles.writeString(trustFile, gson.toJson(trust));
    }

    /**
     * Loads the trust database through encrypted sensitive storage, validates its JSON shape and migrates
     * legacy plaintext bindings as implemented. Malformed state is not a reason to silently invent
     * verified identities.
     *
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    private Map<String, TrustBinding> readTrust() throws IOException {
        if (!Files.exists(trustFile)) {
            return new HashMap<>();
        }
        try {
            boolean legacyPlaintext = !SensitiveFileStore.isEncrypted(trustFile);
            JsonElement parsed = JsonParser.parseString(sensitiveFiles.readString(trustFile));
            if (!parsed.isJsonObject()) {
                throw new IOException("Trust database is not a JSON object");
            }
            Map<String, TrustBinding> trust = new HashMap<>();
            for (Map.Entry<String, JsonElement> entry : parsed.getAsJsonObject().entrySet()) {
                TrustBinding binding = parseBinding(entry.getValue());
                if (binding == null || binding.state() == null
                        || (binding.kemFingerprint() == null) != (binding.signatureFingerprint() == null)) {
                    throw new IOException("Trust binding is invalid for " + entry.getKey());
                }
                trust.put(normalize(entry.getKey()), binding);
            }
            if (legacyPlaintext) {
                sensitiveFiles.writeString(trustFile, gson.toJson(trust));
            }
            return trust;
        } catch (RuntimeException e) {
            throw new IOException("Trust database is invalid", e);
        }
    }

    /**
     * Parses binding for the public-key trust bindings.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     */
    private TrustBinding parseBinding(JsonElement value) {
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
            TrustState legacy = TrustState.valueOf(value.getAsString());
            return new TrustBinding(legacy == TrustState.VERIFIED ? TrustState.TOFU_TRUSTED : legacy, null, null);
        }
        return gson.fromJson(value, TrustBinding.class);
    }

    /**
     * Normalizes the supplied identifier into the comparison/storage form used by the public-key trust
     * bindings.
     *
     * @param player the player supplied to this operation
     * @return the result described above
     */
    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT);
    }

    private record TrustBinding(TrustState state, String kemFingerprint, String signatureFingerprint) {
        /**
         * Resolves the supplied values into the definition used by the public-key trust bindings.
         *
         * @param state the state supplied to this operation
         * @param identity the identity supplied to this operation
         * @return the result described above
         */
        private static TrustBinding of(TrustState state, PublicIdentity identity) {
            return identity == null
                    ? new TrustBinding(state, null, null)
                    : new TrustBinding(state, identity.kemPublicKey().fingerprint(),
                    identity.signaturePublicKey().fingerprint());
        }

        /**
         * Reports whether the public-key trust bindings has fingerprints.
         *
         * @return whether the condition or operation described above succeeds
         */
        private boolean hasFingerprints() {
            return kemFingerprint != null && signatureFingerprint != null;
        }

        /**
         * Performs the matches operation for the public-key trust bindings.
         *
         * @param identity the identity supplied to this operation
         * @return whether the condition or operation described above succeeds
         */
        private boolean matches(PublicIdentity identity) {
            return kemFingerprint.equalsIgnoreCase(identity.kemPublicKey().fingerprint())
                    && signatureFingerprint.equalsIgnoreCase(identity.signaturePublicKey().fingerprint());
        }
    }
}
