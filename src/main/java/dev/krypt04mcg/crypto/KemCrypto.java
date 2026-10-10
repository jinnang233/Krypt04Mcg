package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.compositekem.CompositeIndex;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/** BC-backed KEM operations shared by long-term identities and one-time handshake keys. */
final class KemCrypto {
    private static final int MAGIC = 0x4b303401;
    private static final int MAX_COMPONENT_BYTES = 2 * 1024 * 1024;

    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private KemCrypto() {}

    /**
     * Generates the declared KEM through its explicit provider and parameter specification. Native BC
     * composites remain native; custom hybrids add a freshly generated X25519 or X448 private key and
     * retain the PQ public key needed to bind the hybrid encoding.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param random the randomness source supplied to the cryptographic provider
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    static KeyPair generate(KemAlgorithm algorithm, SecureRandom random) throws GeneralSecurityException {
        KemAlgorithm pqAlgorithm = algorithm.nativeHybrid() ? algorithm : algorithm.postQuantumComponent();
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
        generator.initialize(algorithm.nativeHybrid() ? null : pqAlgorithm.parameterSpec(), random);
        KeyPair pq = generator.generateKeyPair();
        if (!customHybrid(algorithm)) return pq;
        AsymmetricKeyParameter classical = algorithm.classicalAlgorithm().equals("X25519")
                ? new X25519PrivateKeyParameters(random) : new X448PrivateKeyParameters(random);
        return new KeyPair(new HybridPublicKey(pq.getPublic(), publicFromPrivate(classical)),
                new HybridPrivateKey(pq.getPrivate(), classical, pq.getPublic()));
    }

    /**
     * Decodes provider X.509 public keys or versioned custom-hybrid components and verifies exact suite
     * parameters. Custom XDH public inputs are probed for invalid low-order/all-zero agreement behavior
     * before acceptance. Successful import is structural validation, not a peer trust decision.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static PublicKey decodePublic(KemAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PublicKey key;
        if (!customHybrid(algorithm)) {
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
            byte[][] parts = split(encoded, 2);
            PublicKey pq = decodePublic(algorithm.postQuantumComponent(), parts[0]);
            AsymmetricKeyParameter classical = decodeClassical(algorithm, parts[1], false);
            // Validate low-order points on import as well as during encapsulation.
            byte[] probe = agreement(decodeClassical(algorithm, new byte[classicalSize(algorithm)], true), classical);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(probe, (byte) 0);
            key = new HybridPublicKey(pq, classical);
        }
        requireParameters(key, algorithm);
        return key;
    }

    /**
     * Decodes provider PKCS#8 private keys or a bounded three-component hybrid frame including the
     * associated PQ public key. Decoded components are overwritten after construction, and exact
     * parameters are checked before use. Key objects can still hold provider-managed copies.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static PrivateKey decodePrivate(KemAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PrivateKey key;
        if (!customHybrid(algorithm)) {
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
            byte[][] parts = split(encoded, 3);
            try {
                PrivateKey pq = decodePrivate(algorithm.postQuantumComponent(), parts[0]);
                PublicKey pqPublic = decodePublic(algorithm.postQuantumComponent(), parts[2]);
                key = new HybridPrivateKey(pq, decodeClassical(algorithm, parts[1], true), pqPublic);
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
     * Rejects keys that do not match the exact selected KEM. Native composite algorithm identifiers,
     * custom PQ parameters and the X25519/X448 choice are checked separately; no family-name-only fallback
     * is accepted.
     *
     * @param key the cryptographic key material for this operation
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static void requireParameters(Key key, KemAlgorithm algorithm) throws CryptoException {
        if (algorithm.nativeHybrid()) {
            var identifier = switch (key) {
                case CompositePublicKey k -> k.getAlgorithmIdentifier();
                case CompositePrivateKey k -> k.getAlgorithmIdentifier();
                default -> throw new CryptoException("Expected BC composite KEM key");
            };
            if (!algorithm.jcaName().equals(CompositeIndex.getAlgorithmName(identifier.getAlgorithm()))) {
                throw new CryptoException("Composite key does not match the declared KEM");
            }
        } else if (customHybrid(algorithm)) {
            Key pq;
            AsymmetricKeyParameter classical;
            if (key instanceof HybridPublicKey k) {
                pq = k.pq();
                classical = k.classical();
            } else if (key instanceof HybridPrivateKey k) {
                pq = k.pq();
                classical = k.classical();
            } else {
                throw new CryptoException("Expected hybrid KEM key");
            }
            CryptoService.requireKeyParameters(pq, algorithm.parameterSpec());
            boolean x25519 = classical instanceof X25519PublicKeyParameters
                    || classical instanceof X25519PrivateKeyParameters;
            if (x25519 != algorithm.classicalAlgorithm().equals("X25519")) {
                throw new CryptoException("Classical key does not match the declared KEM");
            }
        } else {
            CryptoService.requireKeyParameters(key, algorithm.parameterSpec());
        }
    }

    /**
     * Uses Bouncy Castle KEM generation with withNoKdf to obtain raw primitive secret material and its
     * encapsulation. Custom hybrids additionally generate an ephemeral XDH pair, frame both ciphertext
     * components and combine both shared secrets with domain-separated HKDF. Outer message code derives
     * its own AEAD key from the resulting secret.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param publicKey the public key whose declared suite is checked before use
     * @param random the randomness source supplied to the cryptographic provider
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static SecretKeyWithEncapsulation encapsulate(KemAlgorithm algorithm, PublicKey publicKey, SecureRandom random)
            throws GeneralSecurityException, CryptoException {
        requireParameters(publicKey, algorithm);
        if (!customHybrid(algorithm)) {
            /*
             * Selects the BC KEM implementation for the declared suite. KEMGenerateSpec/KEMExtractSpec request no
             * implicit provider KDF; the application applies its own purpose-separated HKDF to the recovered
             * shared secret.
             */
            var generator = KeyGenerator.getInstance(algorithm.jcaName(), algorithm.provider());
            /*
             * Requests raw KEM shared-secret material with the provider KDF disabled. The AES name/bit length
             * describes the adapter output, not an application encryption operation; message/hybrid code performs
             * its own labeled HKDF before using a key.
             */
            generator.init(new KEMGenerateSpec.Builder(publicKey, "AES", 256).withNoKdf().build(), random);
            return (SecretKeyWithEncapsulation) generator.generateKey();
        }
        var key = (HybridPublicKey) publicKey;
        var pq = encapsulate(algorithm.postQuantumComponent(), key.pq(), random);
        AsymmetricKeyParameter ephemeral = algorithm.classicalAlgorithm().equals("X25519")
                ? new X25519PrivateKeyParameters(random) : new X448PrivateKeyParameters(random);
        byte[] ciphertext = frame(pq.getEncapsulation(), classicalEncoded(publicFromPrivate(ephemeral)));
        return combine(algorithm, pq, agreement(ephemeral, key.classical()), ciphertext, key.getEncoded());
    }

    /**
     * Decapsulates through the explicitly selected provider without its implicit KDF. Custom hybrids parse
     * the bounded frame, recover the PQ secret, perform recipient-side XDH agreement and reproduce the
     * same context-bound HKDF combination. Malformed ciphertext and invalid agreement inputs become
     * checked cryptographic failures.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param privateKey the private key material used by the selected primitive
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static SecretKeyWithEncapsulation extract(KemAlgorithm algorithm, PrivateKey privateKey, byte[] ciphertext)
            throws GeneralSecurityException, CryptoException {
        requireParameters(privateKey, algorithm);
        if (!customHybrid(algorithm)) {
            /*
             * Selects the BC KEM implementation for the declared suite. KEMGenerateSpec/KEMExtractSpec request no
             * implicit provider KDF; the application applies its own purpose-separated HKDF to the recovered
             * shared secret.
             */
            var generator = KeyGenerator.getInstance(algorithm.jcaName(), algorithm.provider());
            /*
             * Requests raw KEM shared-secret material with the provider KDF disabled. The AES name/bit length
             * describes the adapter output, not an application encryption operation; message/hybrid code performs
             * its own labeled HKDF before using a key.
             */
            generator.init(new KEMExtractSpec.Builder(privateKey, ciphertext, "AES", 256).withNoKdf().build());
            try {
                return (SecretKeyWithEncapsulation) generator.generateKey();
            } catch (IllegalArgumentException | IllegalStateException | IndexOutOfBoundsException e) {
                throw new CryptoException("Invalid KEM ciphertext", e);
            }
        }
        var key = (HybridPrivateKey) privateKey;
        byte[][] parts = split(ciphertext, 2);
        AsymmetricKeyParameter classical = decodeClassical(algorithm, parts[1], false);
        var pq = extract(algorithm.postQuantumComponent(), key.pq(), parts[0]);
        byte[] recipient = new HybridPublicKey(key.pqPublic(), publicFromPrivate(key.classical())).getEncoded();
        return combine(algorithm, pq, agreement(key.classical(), classical), ciphertext, recipient);
    }

    /**
     * Returns the custom hybrid value used by the KEM provider and hybrid adapter.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @return whether the condition or operation described above succeeds
     */
    private static boolean customHybrid(KemAlgorithm algorithm) {
        return algorithm.hybrid() && !algorithm.nativeHybrid();
    }

    /**
     * Performs the classical size operation for the KEM provider and hybrid adapter.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @return the result described above
     */
    private static int classicalSize(KemAlgorithm algorithm) {
        return algorithm.classicalAlgorithm().equals("X25519") ? 32 : 56;
    }

    /**
     * Checks the exact 32-byte X25519 or 56-byte X448 encoding length and constructs the corresponding
     * Bouncy Castle private/public parameter object. Low-order public-point rejection is performed by the
     * agreement checks, not by this length check alone.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param encoded the encoded bytes to parse or verify
     * @param privateKey the private key material used by the selected primitive
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static AsymmetricKeyParameter decodeClassical(KemAlgorithm algorithm, byte[] encoded, boolean privateKey)
            throws CryptoException {
        if (encoded.length != classicalSize(algorithm)) throw new CryptoException("Invalid classical key length");
        if (algorithm.classicalAlgorithm().equals("X25519")) {
            return privateKey ? new X25519PrivateKeyParameters(encoded) : new X25519PublicKeyParameters(encoded);
        }
        return privateKey ? new X448PrivateKeyParameters(encoded) : new X448PublicKeyParameters(encoded);
    }

    /**
     * Derives the X25519/X448 public parameter from a supported classical private parameter. Unsupported
     * key types are rejected instead of being reinterpreted.
     *
     * @param key the cryptographic key material for this operation
     * @return the result described above
     */
    private static AsymmetricKeyParameter publicFromPrivate(AsymmetricKeyParameter key) {
        return switch (key) {
            case X25519PrivateKeyParameters k -> k.generatePublicKey();
            case X448PrivateKeyParameters k -> k.generatePublicKey();
            default -> throw new IllegalArgumentException("Unsupported classical private key");
        };
    }

    /**
     * Performs the classical encoded operation for the KEM provider and hybrid adapter.
     *
     * @param key the cryptographic key material for this operation
     * @return the resulting array produced by this operation
     */
    private static byte[] classicalEncoded(AsymmetricKeyParameter key) {
        return switch (key) {
            case X25519PrivateKeyParameters k -> k.getEncoded();
            case X25519PublicKeyParameters k -> k.getEncoded();
            case X448PrivateKeyParameters k -> k.getEncoded();
            case X448PublicKeyParameters k -> k.getEncoded();
            default -> throw new IllegalArgumentException("Unsupported classical key");
        };
    }

    /**
     * Performs X25519 or X448 agreement using Bouncy Castle lightweight key parameters. Invalid/all-zero
     * shared-secret outcomes are rejected; the allocated result is overwritten on failure rather than
     * returned as a usable key.
     *
     * @param privateKey the private key material used by the selected primitive
     * @param publicKey the public key whose declared suite is checked before use
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static byte[] agreement(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey)
            throws CryptoException {
        byte[] secret = new byte[privateKey instanceof X25519PrivateKeyParameters ? 32 : 56];
        try {
            if (privateKey instanceof X25519PrivateKeyParameters k) {
                /*
                 * Delegates X25519/X448 agreement to BC lightweight key parameters. Invalid public inputs and all-zero
                 * shared-secret outcomes are rejected by the surrounding failure path instead of being accepted as
                 * usable secret material.
                 */
                k.generateSecret((X25519PublicKeyParameters) publicKey, secret, 0);
            } else {
                ((X448PrivateKeyParameters) privateKey).generateSecret((X448PublicKeyParameters) publicKey, secret, 0);
            }
            return secret;
        } catch (IllegalStateException e) {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(secret, (byte) 0);
            throw new CryptoException("Invalid classical public key (all-zero shared secret)", e);
        }
    }

    /**
     * Concatenates the PQ and classical shared secrets in a fixed order and derives 32 bytes with
     * HKDF-SHA256. The versioned info frame binds the suite label, complete encapsulation and recipient
     * public-key encoding, separating contexts and preventing ambiguous combinations. Temporary
     * secret/input/result buffers are overwritten in finally; this custom hybrid construction is not
     * asserted to be a standardized combiner.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param pq the pq supplied to this operation
     * @param classicalSecret the classical XDH shared-secret bytes
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @param publicKey the public key whose declared suite is checked before use
     * @return the result described above
     */
    private static SecretKeyWithEncapsulation combine(KemAlgorithm algorithm, SecretKeyWithEncapsulation pq,
                                                       byte[] classicalSecret, byte[] ciphertext, byte[] publicKey) {
        byte[] pqSecret = pq.getEncoded();
        byte[] input = ByteBuffer.allocate(pqSecret.length + classicalSecret.length)
                .put(pqSecret).put(classicalSecret).array();
        byte[] label = ("krypt04mcg hybrid kem v1 " + algorithm.identifier()).getBytes(StandardCharsets.UTF_8);
        byte[] context = frame(label, ciphertext, publicKey);
        byte[] combined = new byte[32];
        try {
            /*
             * Delegates RFC 5869 extract-and-expand to Bouncy Castle with SHA-256. Input secret entropy, salt and
             * purpose-specific info have distinct roles; HKDF does not authenticate those context fields by
             * itself.
             */
            var hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(input, null, context));
            hkdf.generateBytes(combined, 0, combined.length);
            return new SecretKeyWithEncapsulation(new SecretKeySpec(combined, "AES"), ciphertext);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(pqSecret, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(classicalSecret, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(input, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(combined, (byte) 0);
        }
    }

    // Versioned length framing prevents ambiguity, truncation and trailing components.
    /**
     * Serializes the custom hybrid magic and explicit component lengths before each byte array. Length
     * framing removes concatenation ambiguity and permits truncation/trailing-data checks; it does not
     * authenticate the frame by itself.
     *
     * @param components the ordered byte-array components to encode
     * @return the resulting array produced by this operation
     */
    private static byte[] frame(byte[]... components) {
        int size = 4;
        for (byte[] component : components) size += 4 + component.length;
        ByteBuffer buffer = ByteBuffer.allocate(size).putInt(MAGIC);
        for (byte[] component : components) buffer.putInt(component.length).put(component);
        return buffer.array();
    }

    /**
     * Parses the exact expected number of versioned hybrid components under total and per-component
     * bounds. Wrong magic, missing bytes, impossible lengths and trailing components are rejected before
     * use. Partially allocated arrays are overwritten if parsing fails.
     *
     * @param encoded the encoded bytes to parse or verify
     * @param count the required number of frame components
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static byte[][] split(byte[] encoded, int count) throws CryptoException {
        if (encoded == null || encoded.length < 4 + count * 4
                || encoded.length > 4 + count * (4 + MAX_COMPONENT_BYTES)) {
            throw new CryptoException("Invalid hybrid KEM encoding size");
        }
        var buffer = ByteBuffer.wrap(encoded);
        if (buffer.getInt() != MAGIC) throw new CryptoException("Invalid hybrid KEM encoding version");
        byte[][] parts = new byte[count][];
        try {
            for (int i = 0; i < count; i++) {
                if (buffer.remaining() < 4) throw new CryptoException("Truncated hybrid KEM component");
                int size = buffer.getInt();
                if (size < 1 || size > MAX_COMPONENT_BYTES || size > buffer.remaining()) {
                    throw new CryptoException("Invalid hybrid KEM component length");
                }
                parts[i] = new byte[size];
                buffer.get(parts[i]);
            }
            if (buffer.hasRemaining()) throw new CryptoException("Trailing hybrid KEM bytes");
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

    record HybridPublicKey(PublicKey pq, AsymmetricKeyParameter classical) implements PublicKey {
        /**
         * Returns the algorithm exposed by the KEM provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+XDH"; }
        /**
         * Returns the format exposed by the KEM provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getFormat() { return "K04-HYBRID-V1"; }
        /**
         * Exports the versioned custom-hybrid key frame in the component order expected by the decoder.
         * Private-key exports contain secret material; temporary private component copies are overwritten
         * where the implementation provides a finally block, but the returned encoding remains caller-owned
         * sensitive data.
         *
         * @return the resulting array produced by this operation
         */
        @Override public byte[] getEncoded() { return frame(pq.getEncoded(), classicalEncoded(classical)); }
    }

    record HybridPrivateKey(PrivateKey pq, AsymmetricKeyParameter classical, PublicKey pqPublic) implements PrivateKey {
        /**
         * Returns the algorithm exposed by the KEM provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+XDH"; }
        /**
         * Returns the format exposed by the KEM provider and hybrid adapter.
         *
         * @return the result described above
         */
        @Override public String getFormat() { return "K04-HYBRID-V1"; }
        /**
         * Exports the versioned custom-hybrid key frame in the component order expected by the decoder.
         * Private-key exports contain secret material; temporary private component copies are overwritten
         * where the implementation provides a finally block, but the returned encoding remains caller-owned
         * sensitive data.
         *
         * @return the resulting array produced by this operation
         */
        @Override public byte[] getEncoded() {
            byte[] pqBytes = pq.getEncoded();
            byte[] classicalBytes = classicalEncoded(classical);
            try {
                return frame(pqBytes, classicalBytes, pqPublic.getEncoded());
            } finally {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(pqBytes, (byte) 0);
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(classicalBytes, (byte) 0);
            }
        }
    }
}
