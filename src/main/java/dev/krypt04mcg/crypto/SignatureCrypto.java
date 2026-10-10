package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.SignatureAlgorithm;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** BC signs and verifies every component; this class frames and binds custom hybrid suites. */
final class SignatureCrypto {
    private static final int MAGIC = 0x4b345301;
    private static final int MAX_KEY_COMPONENT_BYTES = 4 * 1024 * 1024;
    private static final int MAX_SIGNATURE_COMPONENT_BYTES = 1024 * 1024;
    private static final byte[] DOMAIN = "krypt04mcg hybrid signature v1".getBytes(StandardCharsets.UTF_8);

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private SignatureCrypto() {}

    /**
     * Generates the declared PQ or native composite signature key pair with the explicit provider and
     * parameters. A custom hybrid separately generates its configured Ed25519/Ed448 pair and wraps both
     * keys with the corresponding public identity.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param random the randomness source supplied to the cryptographic provider
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    static KeyPair generate(SignatureAlgorithm algorithm, SecureRandom random) throws GeneralSecurityException {
        SignatureAlgorithm pqAlgorithm = algorithm.postQuantumComponent();
        /*
         * Selects the named JCA key-pair implementation and provider. The adjacent initialization supplies the
         * exact suite parameters and randomness; the library implements the primitive, while project checks
         * bind the resulting key to its declared suite.
         */
        var generator = KeyPairGenerator.getInstance(pqAlgorithm.jcaName(), pqAlgorithm.provider());
        /*
         * Supplies the exact selected key-generation parameter specification to the provider. Where the
         * overload includes SecureRandom it also supplies the configured cryptographic entropy source; test
         * fixtures may select different randomness deliberately.
         */
        generator.initialize(pqAlgorithm.parameterSpec(), random);
        KeyPair pq = generator.generateKeyPair();
        if (!algorithm.customHybrid()) return pq;
        /*
         * Selects the named JCA key-pair implementation and provider. The adjacent initialization supplies the
         * exact suite parameters and randomness; the library implements the primitive, while project checks
         * bind the resulting key to its declared suite.
         */
        var classicalGenerator = KeyPairGenerator.getInstance(algorithm.classicalAlgorithm(), "BC");
        /*
         * Supplies the exact selected key-generation parameter specification to the provider. Where the
         * overload includes SecureRandom it also supplies the configured cryptographic entropy source; test
         * fixtures may select different randomness deliberately.
         */
        classicalGenerator.initialize(new EdDSAParameterSpec(algorithm.classicalAlgorithm()), random);
        KeyPair classical = classicalGenerator.generateKeyPair();
        var publicKey = new HybridPublicKey(pq.getPublic(), classical.getPublic());
        return new KeyPair(publicKey, new HybridPrivateKey(pq.getPrivate(), classical.getPrivate(), publicKey));
    }

    /**
     * Decodes a native/provider public key or a bounded custom-hybrid frame and checks the declared PQ and
     * classical parameter choices. Decoding and parameter matching do not establish trust in a claimed
     * owner.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static PublicKey decodePublic(SignatureAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PublicKey key;
        if (!algorithm.customHybrid()) {
            /*
             * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
             * insufficient: the decoded parameter set and recorded public/private role are checked separately
             * before cryptographic use.
             *
             * Wraps a SubjectPublicKeyInfo-style encoding for the selected provider. Encoded algorithm identifiers
             * and decoded parameter sets must agree with the declared suite; parsing does not establish a trusted
             * owner.
             */
            key = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider())
                    .generatePublic(new X509EncodedKeySpec(encoded));
        } else {
            byte[][] parts = split(encoded, 2, MAX_KEY_COMPONENT_BYTES);
            PublicKey pq = decodePublic(algorithm.postQuantumComponent(), parts[0]);
            /*
             * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
             * insufficient: the decoded parameter set and recorded public/private role are checked separately
             * before cryptographic use.
             *
             * Wraps a SubjectPublicKeyInfo-style encoding for the selected provider. Encoded algorithm identifiers
             * and decoded parameter sets must agree with the declared suite; parsing does not establish a trusted
             * owner.
             */
            PublicKey classical = KeyFactory.getInstance(algorithm.classicalAlgorithm(), "BC")
                    .generatePublic(new X509EncodedKeySpec(parts[1]));
            key = new HybridPublicKey(pq, classical);
        }
        requireParameters(key, algorithm);
        return key;
    }

    /**
     * Decodes provider PKCS#8 material or the custom frame containing PQ private, classical private and
     * corresponding public encodings. Temporary component arrays are overwritten in finally, and declared
     * suite parameters are enforced.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static PrivateKey decodePrivate(SignatureAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PrivateKey key;
        if (!algorithm.customHybrid()) {
            /*
             * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
             * insufficient: the decoded parameter set and recorded public/private role are checked separately
             * before cryptographic use.
             *
             * Wraps private-key encoding for provider PKCS#8 decoding. The bytes contain secrets and may be copied
             * by JCA/provider objects; later array overwriting is best-effort cleanup, not proof that all copies
             * are erased.
             */
            key = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider())
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } else {
            byte[][] parts = split(encoded, 3, MAX_KEY_COMPONENT_BYTES);
            try {
                PrivateKey pq = decodePrivate(algorithm.postQuantumComponent(), parts[0]);
                /*
                 * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
                 * insufficient: the decoded parameter set and recorded public/private role are checked separately
                 * before cryptographic use.
                 *
                 * Wraps private-key encoding for provider PKCS#8 decoding. The bytes contain secrets and may be copied
                 * by JCA/provider objects; later array overwriting is best-effort cleanup, not proof that all copies
                 * are erased.
                 */
                PrivateKey classical = KeyFactory.getInstance(algorithm.classicalAlgorithm(), "BC")
                        .generatePrivate(new PKCS8EncodedKeySpec(parts[1]));
                var publicKey = (HybridPublicKey) decodePublic(algorithm, parts[2]);
                key = new HybridPrivateKey(pq, classical, publicKey);
            } finally {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                for (byte[] part : parts) Arrays.fill(part, (byte) 0);
            }
        }
        requireParameters(key, algorithm);
        return key;
    }

    /**
     * Requires the exact declared signature parameters and key representation. Custom hybrids additionally
     * require the configured EdDSA component and validate the embedded public-key context; incompatible
     * keys fail rather than downgrading.
     *
     * @param key the cryptographic key material for this operation
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static void requireParameters(Key key, SignatureAlgorithm algorithm) throws CryptoException {
        if (!algorithm.customHybrid()) {
            CryptoService.requireSignatureKeyParameters(key, algorithm);
            return;
        }
        Key pq;
        Key classical;
        if (key instanceof HybridPublicKey k) {
            pq = k.pq();
            classical = k.classical();
        } else if (key instanceof HybridPrivateKey k) {
            pq = k.pq();
            classical = k.classical();
            requireParameters(k.publicKey(), algorithm);
        } else {
            throw new CryptoException("Expected custom hybrid signature key");
        }
        CryptoService.requireSignatureKeyParameters(pq, algorithm.postQuantumComponent());
        if (!classical.getAlgorithm().equalsIgnoreCase(algorithm.classicalAlgorithm())) {
            throw new CryptoException("Classical signature key does not match the declared algorithm");
        }
    }

    /**
     * Signs input directly for native/provider suites or signs a shared domain-separated context with both
     * components for custom hybrids. The custom result frames both signatures; the caller must provide
     * canonical authenticated bytes, not an ambiguous object rendering.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param key the cryptographic key material for this operation
     * @param input the input bytes or stream consumed by the operation
     * @param random the randomness source supplied to the cryptographic provider
     * @return the resulting array produced by this operation
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static byte[] sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] input, SecureRandom random)
            throws GeneralSecurityException, CryptoException {
        requireParameters(key, algorithm);
        if (!algorithm.customHybrid()) return signComponent(algorithm.jcaName(), algorithm.provider(), key, input, random);
        var hybrid = (HybridPrivateKey) key;
        byte[] context = context(algorithm, hybrid.publicKey(), input);
        byte[] pq = signComponent(algorithm.jcaName(), algorithm.provider(), hybrid.pq(), context, random);
        byte[] classical = signComponent(algorithm.classicalAlgorithm(), "BC", hybrid.classical(), context, random);
        return frame(pq, classical);
    }

    /**
     * Verifies native/provider signatures or requires both custom-hybrid signatures over the same bound
     * context. Malformed frames and wrong classical signature lengths fail verification, and failure of
     * either component is final; no one-component fallback is accepted. Peer trust and freshness remain
     * separate checks.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param key the cryptographic key material for this operation
     * @param input the input bytes or stream consumed by the operation
     * @param signature the signature bytes or signature representation to verify
     * @return whether the condition or operation described above succeeds
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static boolean verify(SignatureAlgorithm algorithm, PublicKey key, byte[] input, byte[] signature)
            throws GeneralSecurityException, CryptoException {
        requireParameters(key, algorithm);
        if (!algorithm.customHybrid()) return verifyComponent(algorithm.jcaName(), algorithm.provider(), key, input, signature);
        var hybrid = (HybridPublicKey) key;
        byte[][] parts;
        try {
            parts = split(signature, 2, MAX_SIGNATURE_COMPONENT_BYTES);
        } catch (CryptoException e) {
            return false;
        }
        int classicalSize = algorithm.classicalAlgorithm().equals("Ed25519") ? 64 : 114;
        if (parts[1].length != classicalSize) return false;
        byte[] context = context(algorithm, hybrid, input);
        // Both signatures are mandatory. Never accept a single component or fall back.
        return verifyComponent(algorithm.classicalAlgorithm(), "BC", hybrid.classical(), context, parts[1])
                && verifyComponent(algorithm.jcaName(), algorithm.provider(), hybrid.pq(), context, parts[0]);
    }

    /**
     * Initializes the named JCA signature primitive with the explicitly selected provider, private key and
     * supplied SecureRandom, updates it with the complete context, and returns the provider signature. The
     * provider implements primitive padding/prehash rules for that suite.
     *
     * @param name the name supplied to this operation
     * @param provider the explicitly selected JCA provider name
     * @param key the cryptographic key material for this operation
     * @param input the input bytes or stream consumed by the operation
     * @param random the randomness source supplied to the cryptographic provider
     * @return the resulting array produced by this operation
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    private static byte[] signComponent(String name, String provider, PrivateKey key, byte[] input, SecureRandom random)
            throws GeneralSecurityException {
        /*
         * Selects the exact named signature implementation and provider, preserving suite-specific
         * prehash/composite behavior. Key parameters are validated separately; a missing or unsupported
         * implementation is an error, not permission to downgrade.
         */
        var signature = Signature.getInstance(name, provider);
        /*
         * Initializes the selected signature primitive with the private key and supplied cryptographic
         * randomness. Suite-specific rules are implemented by the provider; only the intended canonical
         * context is subsequently fed to it.
         */
        signature.initSign(key, random);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Initializes the named provider signature verifier with the public key and feeds it the same complete
     * context used by signing. The provider checks primitive encoding and signature validity; the
     * application must still require the correct suite and trusted key.
     *
     * @param name the name supplied to this operation
     * @param provider the explicitly selected JCA provider name
     * @param key the cryptographic key material for this operation
     * @param input the input bytes or stream consumed by the operation
     * @param encoded the encoded bytes to parse or verify
     * @return whether the condition or operation described above succeeds
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    private static boolean verifyComponent(String name, String provider, PublicKey key, byte[] input, byte[] encoded)
            throws GeneralSecurityException {
        /*
         * Selects the exact named signature implementation and provider, preserving suite-specific
         * prehash/composite behavior. Key parameters are validated separately; a missing or unsupported
         * implementation is an error, not permission to downgrade.
         */
        var signature = Signature.getInstance(name, provider);
        /*
         * Initializes provider verification with the selected public key. The preceding suite/parameter checks
         * prevent another parameter set from being accepted solely because it shares an algorithm-family name.
         */
        signature.initVerify(key);
        signature.update(input);
        /*
         * Asks the provider to verify the complete supplied signature over the accumulated context. The
         * custom-hybrid caller requires both component verifications; this result alone does not establish
         * user trust or replay freshness.
         */
        return signature.verify(encoded);
    }

    // Fixed-size hashes keep signing costs bounded even for multi-megabyte UOV public keys.
    // Domain, exact suite, both public keys and the message are covered by both components.
    /**
     * Builds a versioned domain-separated signature context containing the exact suite identifier, SHA-512
     * hash of the framed PQ/classical public keys and SHA-512 hash of the input. This binds both
     * components to one key pair and message; it is a project-specific hybrid format rather than a
     * standardized composite encoding.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param publicKey the public key whose declared suite is checked before use
     * @param input the input bytes or stream consumed by the operation
     * @return the resulting array produced by this operation
     */
    private static byte[] context(SignatureAlgorithm algorithm, HybridPublicKey publicKey, byte[] input) {
        return frame(DOMAIN, algorithm.identifier().getBytes(StandardCharsets.UTF_8),
                hash(publicKey.getEncoded()), hash(input));
    }

    /**
     * Computes SHA-512 with JCA for compact context binding. A digest binds bytes in the signed
     * construction but does not independently authenticate a sender or hide low-entropy inputs.
     *
     * @param input the input bytes or stream consumed by the operation
     * @return the resulting array produced by this operation
     */
    private static byte[] hash(byte[] input) {
        var digest = new SHA512Digest();
        digest.update(input, 0, input.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * Encodes the custom signature/key-frame magic and length-prefixed components in a fixed order.
     * Framing prevents ambiguous concatenation; cryptographic authenticity comes from the signature
     * verification path.
     *
     * @param components the ordered byte-array components to encode
     * @return the resulting array produced by this operation
     */
    private static byte[] frame(byte[]... components) {
        int size = 4;
        for (byte[] component : components) size = Math.addExact(size, Math.addExact(4, component.length));
        var buffer = ByteBuffer.allocate(size).putInt(MAGIC);
        for (byte[] component : components) buffer.putInt(component.length).put(component);
        return buffer.array();
    }

    /**
     * Parses a bounded custom frame containing exactly the requested component count. Invalid magic,
     * lengths, truncation and trailing bytes fail closed; allocated parts are overwritten on failure. The
     * caller still validates component-specific sizes and cryptographic signatures.
     *
     * @param encoded the encoded bytes to parse or verify
     * @param count the required number of frame components
     * @param maxComponentBytes the maximum accepted encoded size of each component
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static byte[][] split(byte[] encoded, int count, int maxComponentBytes) throws CryptoException {
        if (encoded == null || encoded.length < 4 + count * 4
                || encoded.length > 4 + count * (4 + maxComponentBytes)) {
            throw new CryptoException("Invalid hybrid signature encoding size");
        }
        var buffer = ByteBuffer.wrap(encoded);
        if (buffer.getInt() != MAGIC) throw new CryptoException("Invalid hybrid signature encoding version");
        byte[][] parts = new byte[count][];
        try {
            for (int i = 0; i < count; i++) {
                if (buffer.remaining() < 4) throw new CryptoException("Truncated hybrid signature component");
                int size = buffer.getInt();
                if (size < 1 || size > maxComponentBytes || size > buffer.remaining()) {
                    throw new CryptoException("Invalid hybrid signature component length");
                }
                parts[i] = new byte[size];
                buffer.get(parts[i]);
            }
            if (buffer.hasRemaining()) throw new CryptoException("Trailing hybrid signature bytes");
            return parts;
        } catch (CryptoException e) {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            for (byte[] part : parts) if (part != null) Arrays.fill(part, (byte) 0);
            throw e;
        }
    }

    record HybridPublicKey(PublicKey pq, PublicKey classical) implements PublicKey {
        /**
         * Returns the algorithm exposed by the signature provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+" + classical.getAlgorithm(); }
        /**
         * Returns the format exposed by the signature provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getFormat() { return "K04-HYBRID-SIGNATURE-V1"; }
        /**
         * Exports a versioned custom-hybrid key frame. Public encodings bind both component keys; private
         * encodings also include the associated public frame and contain caller-owned secret bytes. Temporary
         * private component encodings are overwritten in finally.
         *
         * @return the resulting array produced by this operation
         */
        @Override public byte[] getEncoded() { return frame(pq.getEncoded(), classical.getEncoded()); }
    }

    record HybridPrivateKey(PrivateKey pq, PrivateKey classical, HybridPublicKey publicKey) implements PrivateKey {
        /**
         * Returns the algorithm exposed by the signature provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+" + classical.getAlgorithm(); }
        /**
         * Returns the format exposed by the signature provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getFormat() { return "K04-HYBRID-SIGNATURE-V1"; }
        /**
         * Exports a versioned custom-hybrid key frame. Public encodings bind both component keys; private
         * encodings also include the associated public frame and contain caller-owned secret bytes. Temporary
         * private component encodings are overwritten in finally.
         *
         * @return the resulting array produced by this operation
         */
        @Override public byte[] getEncoded() {
            byte[] pqEncoded = pq.getEncoded();
            byte[] classicalEncoded = classical.getEncoded();
            try {
                return frame(pqEncoded, classicalEncoded, publicKey.getEncoded());
            } finally {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(pqEncoded, (byte) 0);
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(classicalEncoded, (byte) 0);
            }
        }
    }
}
