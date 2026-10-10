package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SlhDsaSignatureAlgorithmTest {
    private static final byte[] MESSAGE = "SLH-DSA variant test".getBytes(StandardCharsets.UTF_8);

    /**
     * Provides the install provider fixture operation used by the slh dsa signature algorithm test
     * regression scenarios.
     */
    @BeforeAll
    static void installProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Verifies that exposes every bouncy castle slh dsa variant.
     */
    @Test
    void exposesEveryBouncyCastleSlhDsaVariant() {
        assertEquals(24, slhDsaAlgorithms().size());
    }

    /**
     * Verifies that largest slh dsa signature survives default packet fragmentation.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void largestSlhDsaSignatureSurvivesDefaultPacketFragmentation() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid", KemAlgorithm.ML_KEM_512,
                SignatureAlgorithm.SLH_DSA_SHA2_256F_ED448);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid", KemAlgorithm.HQC_HQC256_X448,
                SignatureAlgorithm.FALCON_512);
        PublicIdentity alicePublic = publicIdentity(alice);
        PublicIdentity bobPublic = publicIdentity(bob);
        char[] chars = new char[CryptoService.MAX_PLAINTEXT_BYTES];
        var random = new java.util.Random(42);
        for (int i = 0; i < chars.length; i++) chars[i] = (char) (32 + random.nextInt(95));
        String plaintext = new String(chars);
        // Disable compression so the full 64 KiB ciphertext is exercised.
        EncryptedPacket packet = crypto.encryptFor(bobPublic, alice, "alice", plaintext, true, false,
                dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);
        assertEquals(49_982, packet.signature().length);
        assertEquals(65_552, packet.ciphertext().length);

        PacketCodec codec = new PacketCodec();
        FragmentService fragmentService = new FragmentService();
        List<String> encodedFragments = fragmentService.fragment(codec.encode(packet), packet.messageId(), 180);
        assertTrue(encodedFragments.size() > 512);
        assertTrue(encodedFragments.size() <= FragmentReassembler.DEFAULT_MAX_FRAGMENTS_PER_MESSAGE);

        FragmentReassembler reassembler = new FragmentReassembler();
        Optional<byte[]> reassembled = Optional.empty();
        for (String encodedFragment : encodedFragments) {
            Fragment fragment = fragmentService.parse(encodedFragment);
            reassembled = reassembler.accept(fragment);
        }

        EncryptedPacket decoded = codec.decode(reassembled.orElseThrow());
        assertEquals(plaintext, crypto.decrypt(decoded, bob, alicePublic));
    }

    /**
     * Verifies that every slh dsa variant generates persists signs and verifies.
     *
     * @return the result described above
     */
    @TestFactory
    Stream<DynamicTest> everySlhDsaVariantGeneratesPersistsSignsAndVerifies() {
        return slhDsaAlgorithms().stream()
                .map(algorithm -> DynamicTest.dynamicTest(algorithm.identifier(), () -> exercise(algorithm)));
    }

    /**
     * Provides the slh dsa algorithms fixture operation used by the slh dsa signature algorithm test
     * regression scenarios.
     *
     * @return the result described above
     */
    private static List<SignatureAlgorithm> slhDsaAlgorithms() {
        return Stream.of(SignatureAlgorithm.values())
                .filter(algorithm -> !algorithm.hybrid() && algorithm.identifier().startsWith("SLH-DSA-"))
                .toList();
    }

    /**
     * Provides the exercise fixture operation used by the slh dsa signature algorithm test regression
     * scenarios.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private static void exercise(SignatureAlgorithm algorithm) throws Exception {
        /*
         * Selects the named JCA key-pair implementation and provider. The adjacent initialization supplies the
         * exact suite parameters and randomness; the library implements the primitive, while project checks
         * bind the resulting key to its declared suite.
         */
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.jcaName(), algorithm.provider());
        /*
         * Supplies the exact selected key-generation parameter specification to the provider. Where the
         * overload includes SecureRandom it also supplies the configured cryptographic entropy source; test
         * fixtures may select different randomness deliberately.
         */
        generator.initialize(algorithm.parameterSpec());
        KeyPair generated = generator.generateKeyPair();

        /*
         * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
         * insufficient: the decoded parameter set and recorded public/private role are checked separately
         * before cryptographic use.
         */
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider());
        /*
         * Wraps private-key encoding for provider PKCS#8 decoding. The bytes contain secrets and may be copied
         * by JCA/provider objects; later array overwriting is best-effort cleanup, not proof that all copies
         * are erased.
         */
        var privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(generated.getPrivate().getEncoded()));
        /*
         * Wraps a SubjectPublicKeyInfo-style encoding for the selected provider. Encoded algorithm identifiers
         * and decoded parameter sets must agree with the declared suite; parsing does not establish a trusted
         * owner.
         */
        var publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(generated.getPublic().getEncoded()));

        /*
         * Selects the exact named signature implementation and provider, preserving suite-specific
         * prehash/composite behavior. Key parameters are validated separately; a missing or unsupported
         * implementation is an error, not permission to downgrade.
         */
        Signature signer = Signature.getInstance(algorithm.jcaName(), algorithm.provider());
        signer.initSign(privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        /*
         * Selects the exact named signature implementation and provider, preserving suite-specific
         * prehash/composite behavior. Key parameters are validated separately; a missing or unsupported
         * implementation is an error, not permission to downgrade.
         */
        Signature verifier = Signature.getInstance(algorithm.jcaName(), algorithm.provider());
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        assertTrue(verifier.verify(signature));
    }

    /**
     * Provides the public identity fixture operation used by the slh dsa signature algorithm test
     * regression scenarios.
     *
     * @param material the material supplied to this operation
     * @return the result described above
     */
    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }
}
