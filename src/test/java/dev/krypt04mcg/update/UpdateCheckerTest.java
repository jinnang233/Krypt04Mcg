package dev.krypt04mcg.update;

import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class UpdateCheckerTest {
    private static final String METADATA_JSON =
            "{\"tag\":\"v1.2.3\",\"mod_version_fabric\":\"1.2.3\",\"mod_version_neoforge\":\"1.2.3\"}";

    /**
     * Installs the Bouncy Castle provider used by the update-signature regression scenarios.
     */
    @BeforeAll
    static void installProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Verifies numeric segment comparison rather than string ordering.
     */
    @Test
    void comparesNumericVersionSegments() {
        assertTrue(UpdateChecker.compareVersions("1.10.0", "1.9.9") > 0);
        assertTrue(UpdateChecker.compareVersions("0.29.4", "0.30.0") < 0);
        assertEquals(0, UpdateChecker.compareVersions("1.2", "1.2.0"));
        assertEquals(0, UpdateChecker.compareVersions("1.02.3", "1.2.3"));
        assertTrue(UpdateChecker.isNewer("1.2.4", "1.2.3"));
        assertFalse(UpdateChecker.isNewer("1.2.3", "1.2.3"));
        assertFalse(UpdateChecker.isNewer("1.2.4", "dev-build"));
    }

    /**
     * Verifies that both loader version fields are parsed and a matching tag is required.
     *
     * @throws Exception if the fixture cannot be parsed
     */
    @Test
    void parsesLoaderSpecificMetadata() throws Exception {
        byte[] metadata = METADATA_JSON.getBytes(StandardCharsets.UTF_8);
        assertEquals("1.2.3", UpdateChecker.parseMetadata(metadata, UpdateChecker.Loader.FABRIC).version());
        assertEquals("1.2.3", UpdateChecker.parseMetadata(metadata, UpdateChecker.Loader.NEOFORGE).version());
        assertEquals("v1.2.3", UpdateChecker.parseMetadata(metadata, UpdateChecker.Loader.FABRIC).tag());
    }

    /**
     * Verifies that snapshot tags, malformed versions and tag/version disagreements are rejected.
     */
    @Test
    void rejectsMetadataThatIsNotAStableMatchingRelease() {
        assertRejected("{\"tag\":\"snapshot-20260101-000000\",\"mod_version_fabric\":\"1.2.3\"}");
        assertRejected("{\"tag\":\"v1.2.3\",\"mod_version_fabric\":\"1.2.4\"}");
        assertRejected("{\"tag\":\"v1.2.3\",\"mod_version_fabric\":\"1.2.3-beta\"}");
        assertRejected("{\"tag\":\"v1.2.3\",\"mod_version_fabric\":1.2}");
        assertRejected("not json");
    }

    /**
     * Verifies that a correctly signed newer release is accepted and mapped to its release page.
     *
     * @throws Exception if the fixture signature cannot be produced
     */
    @Test
    void acceptsSignedNewerRelease() throws Exception {
        KeyPair pair = generateKeyPair();
        byte[] metadata = METADATA_JSON.getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(pair, metadata);

        Optional<UpdateChecker.UpdateInfo> update = UpdateChecker.evaluate(
                metadata, signature, pair.getPublic(), "1.2.2", UpdateChecker.Loader.FABRIC);

        assertTrue(update.isPresent());
        assertEquals("v1.2.3", update.orElseThrow().tag());
        assertEquals("1.2.3", update.orElseThrow().version());
        assertEquals(UpdateChecker.RELEASE_PAGE_PREFIX + "v1.2.3", update.orElseThrow().releasePageUrl());
    }

    /**
     * Verifies that altered metadata bytes fail verification even when the JSON stays valid.
     *
     * @throws Exception if the fixture signature cannot be produced
     */
    @Test
    void rejectsTamperedOrMismatchedSignedMetadata() throws Exception {
        KeyPair pair = generateKeyPair();
        byte[] metadata = METADATA_JSON.getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(pair, metadata);

        byte[] tampered = (METADATA_JSON + " ").getBytes(StandardCharsets.UTF_8);
        assertTrue(UpdateChecker.evaluate(tampered, signature, pair.getPublic(), "1.2.2",
                UpdateChecker.Loader.FABRIC).isEmpty());

        byte[] mismatched = "{\"tag\":\"v1.2.4\",\"mod_version_fabric\":\"1.2.3\"}"
                .getBytes(StandardCharsets.UTF_8);
        assertTrue(UpdateChecker.evaluate(mismatched, sign(pair, mismatched), pair.getPublic(), "1.2.2",
                UpdateChecker.Loader.FABRIC).isEmpty());
    }

    /**
     * Verifies that the bundled key is a SLH-DSA-SHAKE-256f public key.
     *
     * @throws Exception if the bundled key cannot be loaded
     */
    @Test
    void loadsBundledSlhDsaSigningKey() throws Exception {
        PublicKey key = UpdateChecker.loadPublicKey();
        assertTrue(key.getAlgorithm().toUpperCase(java.util.Locale.ROOT).contains("SLH-DSA-SHAKE-256F"));
    }

    /**
     * Asserts that the supplied metadata is rejected by the parser.
     *
     * @param json the metadata fixture
     */
    private static void assertRejected(String json) {
        try {
            UpdateChecker.parseMetadata(json.getBytes(StandardCharsets.UTF_8), UpdateChecker.Loader.FABRIC);
            throw new AssertionError("Expected metadata to be rejected: " + json);
        } catch (java.io.IOException expected) {
            assertFalse(expected.getMessage().isBlank());
        }
    }

    /**
     * Generates a SLH-DSA-SHAKE-256f key pair for a signature fixture.
     *
     * @return the generated key pair
     * @throws Exception if the provider cannot generate the key pair
     */
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        generator.initialize(SLHDSAParameterSpec.slh_dsa_shake_256f);
        return generator.generateKeyPair();
    }

    /**
     * Signs the supplied fixture bytes with the generated private key.
     *
     * @param pair the signing key pair
     * @param message the message bytes
     * @return the detached signature
     * @throws Exception if signing fails
     */
    private static byte[] sign(KeyPair pair, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("SLH-DSA-SHAKE-256F", "BC");
        signer.initSign(pair.getPrivate());
        signer.update(message);
        return signer.sign();
    }
}
