package dev.krypt04mcg.update;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Checks the published GitHub release metadata for a newer mod version.
 *
 * <p>The release metadata and its detached signature are fetched over HTTPS, and the signature is
 * verified with the public key bundled in this mod before any field is used. The downloaded key
 * shown on the release page is intentionally not trusted for verification. The check never
 * downloads or executes a release artifact; it only reports the release page to the player.</p>
 */
public final class UpdateChecker {
    public static final String LATEST_METADATA_URL =
            "https://github.com/jinnang233/Krypt04Mcg/releases/latest/download/latest.json";
    public static final String RELEASE_PAGE_PREFIX =
            "https://github.com/jinnang233/Krypt04Mcg/releases/tag/";

    private static final Logger LOGGER = LoggerFactory.getLogger("krypt04mcg-update");
    private static final String SIGNATURE_SUFFIX = ".sign";
    private static final String PUBLIC_KEY_RESOURCE = "/krypt04mcg.pub";
    private static final String SLH_DSA_SHAKE_256F = "SLH-DSA-SHAKE-256F";
    private static final String KEY_ALGORITHM = "SLH-DSA";
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final int MAX_METADATA_BYTES = 16 * 1024;
    private static final int MAX_SIGNATURE_BYTES = 64 * 1024;
    private static final int MAX_PUBLIC_KEY_BYTES = 4 * 1024;
    private static final int MAX_VERSION_LENGTH = 64;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
    private static final Pattern VERSION_TAG = Pattern.compile("^v[0-9]+(?:\\.[0-9]+)*$");
    private static final Pattern VERSION_FIELD = Pattern.compile("^[0-9]+(?:\\.[0-9]+)*$");

    private static final URI METADATA_URI = URI.create(LATEST_METADATA_URL);
    private static final URI SIGNATURE_URI = URI.create(LATEST_METADATA_URL + SIGNATURE_SUFFIX);

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private UpdateChecker() {
    }

    /**
     * Selects the loader-specific version field in the signed release metadata.
     */
    public enum Loader {
        FABRIC("mod_version_fabric"),
        NEOFORGE("mod_version_neoforge");

        private final String versionField;

        Loader(String versionField) {
            this.versionField = versionField;
        }

        String versionField() {
            return versionField;
        }
    }

    /**
     * Reports a newer release whose metadata passed signature verification.
     *
     * @param tag the release tag, for example {@code v0.29.5}
     * @param version the loader-specific mod version
     * @param releasePageUrl the GitHub release page shown to the player
     */
    public record UpdateInfo(String tag, String version, String releasePageUrl) {
    }

    /**
     * Runs one update check on a daemon thread and invokes the listener only when the signature
     * verifies and a newer version is published. Network and verification failures are logged and
     * otherwise ignored.
     *
     * @param currentVersion the installed mod version
     * @param loader the loader whose metadata version field applies
     * @param onUpdate the listener invoked with a verified newer release
     */
    public static void checkAsync(String currentVersion, Loader loader, Consumer<UpdateInfo> onUpdate) {
        Thread thread = new Thread(() -> {
            try {
                check(currentVersion, loader).ifPresent(onUpdate);
            } catch (Exception e) {
                LOGGER.debug("Krypt04Mcg update check failed", e);
            }
        }, "krypt04mcg-update-check");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Fetches and verifies the release metadata once.
     *
     * @param currentVersion the installed mod version
     * @param loader the loader whose metadata version field applies
     * @return the verified newer release, if available
     * @throws Exception if the metadata cannot be fetched or the key cannot be loaded
     */
    static Optional<UpdateInfo> check(String currentVersion, Loader loader) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        byte[] metadata = fetch(client, METADATA_URI, MAX_METADATA_BYTES);
        byte[] signature = fetch(client, SIGNATURE_URI, MAX_SIGNATURE_BYTES);
        return evaluate(metadata, signature, loadPublicKey(), currentVersion, loader);
    }

    /**
     * Verifies the detached signature over the exact metadata bytes before parsing any field.
     *
     * @param metadata the exact bytes covered by the signature
     * @param signature the detached signature
     * @param publicKey the bundled update-signing key
     * @param currentVersion the installed mod version
     * @param loader the loader whose metadata version field applies
     * @return the verified newer release, if available
     */
    static Optional<UpdateInfo> evaluate(byte[] metadata, byte[] signature, PublicKey publicKey,
                                         String currentVersion, Loader loader) {
        if (!verifyDetachedSignature(metadata, signature, publicKey)) {
            LOGGER.warn("Ignoring Krypt04Mcg update metadata: signature verification failed");
            return Optional.empty();
        }
        LatestMetadata latest;
        try {
            latest = parseMetadata(metadata, loader);
        } catch (IOException e) {
            LOGGER.warn("Ignoring Krypt04Mcg update metadata: {}", e.getMessage());
            return Optional.empty();
        }
        if (!isNewer(latest.version(), currentVersion)) {
            return Optional.empty();
        }
        return Optional.of(new UpdateInfo(latest.tag(), latest.version(), RELEASE_PAGE_PREFIX + latest.tag()));
    }

    /**
     * Verifies a detached SLH-DSA-SHAKE-256f signature over the supplied bytes.
     *
     * @param message the signed message bytes
     * @param signature the detached signature bytes
     * @param publicKey the signing public key
     * @return whether the signature is valid for this exact message
     */
    static boolean verifyDetachedSignature(byte[] message, byte[] signature, PublicKey publicKey) {
        if (message == null || signature == null || publicKey == null
                || signature.length == 0 || signature.length > MAX_SIGNATURE_BYTES) {
            return false;
        }
        try {
            ensureProviders();
            Signature verifier = Signature.getInstance(SLH_DSA_SHAKE_256F, BC);
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception e) {
            LOGGER.warn("Unable to verify the Krypt04Mcg update signature", e);
            return false;
        }
    }

    /**
     * Loads the update-signing public key bundled with the mod. The key is pinned to
     * SLH-DSA-SHAKE-256f so a substituted key of another type is rejected.
     *
     * @return the bundled public key
     * @throws Exception if the resource is missing, malformed or uses another algorithm
     */
    static PublicKey loadPublicKey() throws Exception {
        byte[] pem;
        try (InputStream in = UpdateChecker.class.getResourceAsStream(PUBLIC_KEY_RESOURCE)) {
            if (in == null) {
                throw new IOException("Bundled update public key is missing");
            }
            pem = in.readNBytes(MAX_PUBLIC_KEY_BYTES + 1);
        }
        if (pem.length > MAX_PUBLIC_KEY_BYTES) {
            throw new IOException("Bundled update public key is too large");
        }
        ensureProviders();
        PublicKey key = KeyFactory.getInstance(KEY_ALGORITHM, BC)
                .generatePublic(new X509EncodedKeySpec(decodePem(pem)));
        if (!SLH_DSA_SHAKE_256F.equalsIgnoreCase(key.getAlgorithm())) {
            throw new IOException("Bundled update public key has an unexpected algorithm");
        }
        return key;
    }

    /**
     * Parses the already-verified release metadata and requires the tag and version field to
     * describe the same numeric version. Snapshot tags are ignored.
     *
     * @param metadata the verified metadata bytes
     * @param loader the loader whose metadata version field applies
     * @return the parsed release metadata
     * @throws IOException if a required field is missing or malformed
     */
    static LatestMetadata parseMetadata(byte[] metadata, Loader loader) throws IOException {
        JsonObject object;
        try {
            JsonElement parsed = JsonParser.parseString(new String(metadata, StandardCharsets.UTF_8));
            if (!parsed.isJsonObject()) {
                throw new IOException("Update metadata is not a JSON object");
            }
            object = parsed.getAsJsonObject();
        } catch (RuntimeException e) {
            throw new IOException("Update metadata is not valid JSON", e);
        }
        String tag = requireString(object, "tag");
        String version = requireString(object, loader.versionField());
        if (tag.length() > MAX_VERSION_LENGTH || !VERSION_TAG.matcher(tag).matches()) {
            throw new IOException("Update metadata tag is not a supported release tag");
        }
        if (version.length() > MAX_VERSION_LENGTH || !VERSION_FIELD.matcher(version).matches()) {
            throw new IOException("Update metadata version is malformed");
        }
        if (compareVersions(tag.substring(1), version) != 0) {
            throw new IOException("Update metadata tag and version disagree");
        }
        return new LatestMetadata(tag, version);
    }

    /**
     * Compares two dotted numeric versions segment by segment. Missing trailing segments count as
     * zero; leading zeroes are ignored.
     *
     * @param left the left-hand version
     * @param right the right-hand version
     * @return a negative number, zero, or a positive number as {@code left} is older, equal or newer
     * @throws IllegalArgumentException if either version is malformed
     */
    static int compareVersions(String left, String right) {
        String[] leftParts = versionParts(left);
        String[] rightParts = versionParts(right);
        int length = Math.max(leftParts.length, rightParts.length);
        for (int i = 0; i < length; i++) {
            BigInteger leftPart = i < leftParts.length ? new BigInteger(leftParts[i]) : BigInteger.ZERO;
            BigInteger rightPart = i < rightParts.length ? new BigInteger(rightParts[i]) : BigInteger.ZERO;
            int compared = leftPart.compareTo(rightPart);
            if (compared != 0) {
                return compared;
            }
        }
        return 0;
    }

    /**
     * Reports whether the candidate version is newer than the installed version. An unparseable
     * installed version is treated as current so development builds are not prompted.
     *
     * @param candidate the published version
     * @param current the installed version
     * @return whether an update should be reported
     */
    static boolean isNewer(String candidate, String current) {
        try {
            return compareVersions(candidate, current) > 0;
        } catch (IllegalArgumentException e) {
            LOGGER.debug("Cannot compare installed Krypt04Mcg version '{}'", current);
            return false;
        }
    }

    /**
     * Splits and validates a dotted numeric version.
     *
     * @param value the version to split
     * @return the validated segments
     */
    private static String[] versionParts(String value) {
        if (value == null || value.length() > MAX_VERSION_LENGTH || !VERSION_FIELD.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid version: " + value);
        }
        return value.split("\\.");
    }

    /**
     * Reads one required string field.
     *
     * @param object the metadata object
     * @param field the field name
     * @return the field value
     * @throws IOException if the field is missing or not a string
     */
    private static String requireString(JsonObject object, String field) throws IOException {
        JsonElement element = object.get(field);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
            throw new IOException("Update metadata is missing string field " + field);
        }
        return element.getAsString();
    }

    /**
     * Fetches a bounded response over HTTPS. Redirects are followed, but a redirect that leaves
     * HTTPS is rejected before the body is read.
     *
     * @param client the HTTP client
     * @param uri the request URI
     * @param maxBytes the maximum accepted body size
     * @return the response bytes
     * @throws IOException if the response is unsuccessful or too large
     * @throws InterruptedException if the request is interrupted
     */
    private static byte[] fetch(HttpClient client, URI uri, int maxBytes)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/json, application/octet-stream")
                .header("User-Agent", "Krypt04Mcg-UpdateChecker")
                .GET()
                .build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            if (!"https".equalsIgnoreCase(response.uri().getScheme())) {
                throw new IOException("Update response is not HTTPS");
            }
            if (response.statusCode() != 200) {
                throw new IOException("Update request failed with HTTP " + response.statusCode());
            }
            byte[] data = body.readNBytes(maxBytes + 1);
            if (data.length > maxBytes) {
                throw new IOException("Update response is too large");
            }
            return data;
        }
    }

    /**
     * Decodes a PEM SubjectPublicKeyInfo document into DER.
     *
     * @param pem the PEM document bytes
     * @return the DER-encoded key
     * @throws IOException if the PEM framing or base64 body is invalid
     */
    private static byte[] decodePem(byte[] pem) throws IOException {
        String begin = "-----BEGIN PUBLIC KEY-----";
        String end = "-----END PUBLIC KEY-----";
        String text = new String(pem, StandardCharsets.US_ASCII);
        int start = text.indexOf(begin);
        int finish = text.indexOf(end, start < 0 ? 0 : start + begin.length());
        if (start < 0 || finish < 0) {
            throw new IOException("Bundled update public key is not PEM encoded");
        }
        try {
            return Base64.getMimeDecoder().decode(text.substring(start + begin.length(), finish));
        } catch (IllegalArgumentException e) {
            throw new IOException("Bundled update public key is malformed", e);
        }
    }

    /**
     * Registers the Bouncy Castle provider when it is not already installed.
     */
    private static void ensureProviders() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * The verified fields used for the update decision.
     *
     * @param tag the release tag
     * @param version the loader-specific version
     */
    record LatestMetadata(String tag, String version) {
    }
}
