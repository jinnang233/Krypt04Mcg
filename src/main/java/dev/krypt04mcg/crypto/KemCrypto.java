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

    private KemCrypto() {}

    static KeyPair generate(KemAlgorithm algorithm, SecureRandom random) throws GeneralSecurityException {
        KemAlgorithm pqAlgorithm = algorithm.nativeHybrid() ? algorithm : algorithm.postQuantumComponent();
        var generator = KeyPairGenerator.getInstance(pqAlgorithm.jcaName(), pqAlgorithm.provider());
        generator.initialize(algorithm.nativeHybrid() ? null : pqAlgorithm.parameterSpec(), random);
        KeyPair pq = generator.generateKeyPair();
        if (!customHybrid(algorithm)) return pq;
        AsymmetricKeyParameter classical = algorithm.classicalAlgorithm().equals("X25519")
                ? new X25519PrivateKeyParameters(random) : new X448PrivateKeyParameters(random);
        return new KeyPair(new HybridPublicKey(pq.getPublic(), publicFromPrivate(classical)),
                new HybridPrivateKey(pq.getPrivate(), classical, pq.getPublic()));
    }

    static PublicKey decodePublic(KemAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PublicKey key;
        if (!customHybrid(algorithm)) {
            key = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider())
                    .generatePublic(new X509EncodedKeySpec(encoded));
        } else {
            byte[][] parts = split(encoded, 2);
            PublicKey pq = decodePublic(algorithm.postQuantumComponent(), parts[0]);
            AsymmetricKeyParameter classical = decodeClassical(algorithm, parts[1], false);
            // Validate low-order points on import as well as during encapsulation.
            byte[] probe = agreement(decodeClassical(algorithm, new byte[classicalSize(algorithm)], true), classical);
            Arrays.fill(probe, (byte) 0);
            key = new HybridPublicKey(pq, classical);
        }
        requireParameters(key, algorithm);
        return key;
    }

    static PrivateKey decodePrivate(KemAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PrivateKey key;
        if (!customHybrid(algorithm)) {
            key = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider())
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } else {
            byte[][] parts = split(encoded, 3);
            try {
                PrivateKey pq = decodePrivate(algorithm.postQuantumComponent(), parts[0]);
                PublicKey pqPublic = decodePublic(algorithm.postQuantumComponent(), parts[2]);
                key = new HybridPrivateKey(pq, decodeClassical(algorithm, parts[1], true), pqPublic);
            } finally {
                for (byte[] part : parts) Arrays.fill(part, (byte) 0);
            }
        }
        requireParameters(key, algorithm);
        return key;
    }

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

    static SecretKeyWithEncapsulation encapsulate(KemAlgorithm algorithm, PublicKey publicKey, SecureRandom random)
            throws GeneralSecurityException, CryptoException {
        requireParameters(publicKey, algorithm);
        if (!customHybrid(algorithm)) {
            var generator = KeyGenerator.getInstance(algorithm.jcaName(), algorithm.provider());
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

    static SecretKeyWithEncapsulation extract(KemAlgorithm algorithm, PrivateKey privateKey, byte[] ciphertext)
            throws GeneralSecurityException, CryptoException {
        requireParameters(privateKey, algorithm);
        if (!customHybrid(algorithm)) {
            var generator = KeyGenerator.getInstance(algorithm.jcaName(), algorithm.provider());
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

    private static boolean customHybrid(KemAlgorithm algorithm) {
        return algorithm.hybrid() && !algorithm.nativeHybrid();
    }

    private static int classicalSize(KemAlgorithm algorithm) {
        return algorithm.classicalAlgorithm().equals("X25519") ? 32 : 56;
    }

    private static AsymmetricKeyParameter decodeClassical(KemAlgorithm algorithm, byte[] encoded, boolean privateKey)
            throws CryptoException {
        if (encoded.length != classicalSize(algorithm)) throw new CryptoException("Invalid classical key length");
        if (algorithm.classicalAlgorithm().equals("X25519")) {
            return privateKey ? new X25519PrivateKeyParameters(encoded) : new X25519PublicKeyParameters(encoded);
        }
        return privateKey ? new X448PrivateKeyParameters(encoded) : new X448PublicKeyParameters(encoded);
    }

    private static AsymmetricKeyParameter publicFromPrivate(AsymmetricKeyParameter key) {
        return switch (key) {
            case X25519PrivateKeyParameters k -> k.generatePublicKey();
            case X448PrivateKeyParameters k -> k.generatePublicKey();
            default -> throw new IllegalArgumentException("Unsupported classical private key");
        };
    }

    private static byte[] classicalEncoded(AsymmetricKeyParameter key) {
        return switch (key) {
            case X25519PrivateKeyParameters k -> k.getEncoded();
            case X25519PublicKeyParameters k -> k.getEncoded();
            case X448PrivateKeyParameters k -> k.getEncoded();
            case X448PublicKeyParameters k -> k.getEncoded();
            default -> throw new IllegalArgumentException("Unsupported classical key");
        };
    }

    private static byte[] agreement(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey)
            throws CryptoException {
        byte[] secret = new byte[privateKey instanceof X25519PrivateKeyParameters ? 32 : 56];
        try {
            if (privateKey instanceof X25519PrivateKeyParameters k) {
                k.generateSecret((X25519PublicKeyParameters) publicKey, secret, 0);
            } else {
                ((X448PrivateKeyParameters) privateKey).generateSecret((X448PublicKeyParameters) publicKey, secret, 0);
            }
            return secret;
        } catch (IllegalStateException e) {
            Arrays.fill(secret, (byte) 0);
            throw new CryptoException("Invalid classical public key (all-zero shared secret)", e);
        }
    }

    private static SecretKeyWithEncapsulation combine(KemAlgorithm algorithm, SecretKeyWithEncapsulation pq,
                                                       byte[] classicalSecret, byte[] ciphertext, byte[] publicKey) {
        byte[] pqSecret = pq.getEncoded();
        byte[] input = ByteBuffer.allocate(pqSecret.length + classicalSecret.length)
                .put(pqSecret).put(classicalSecret).array();
        byte[] label = ("krypt04mcg hybrid kem v1 " + algorithm.identifier()).getBytes(StandardCharsets.UTF_8);
        byte[] context = frame(label, ciphertext, publicKey);
        byte[] combined = new byte[32];
        try {
            var hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(input, null, context));
            hkdf.generateBytes(combined, 0, combined.length);
            return new SecretKeyWithEncapsulation(new SecretKeySpec(combined, "AES"), ciphertext);
        } finally {
            Arrays.fill(pqSecret, (byte) 0);
            Arrays.fill(classicalSecret, (byte) 0);
            Arrays.fill(input, (byte) 0);
            Arrays.fill(combined, (byte) 0);
        }
    }

    // Versioned length framing prevents ambiguity, truncation and trailing components.
    private static byte[] frame(byte[]... components) {
        int size = 4;
        for (byte[] component : components) size += 4 + component.length;
        ByteBuffer buffer = ByteBuffer.allocate(size).putInt(MAGIC);
        for (byte[] component : components) buffer.putInt(component.length).put(component);
        return buffer.array();
    }

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
            for (byte[] part : parts) if (part != null) Arrays.fill(part, (byte) 0);
            throw e;
        }
    }

    record HybridPublicKey(PublicKey pq, AsymmetricKeyParameter classical) implements PublicKey {
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+XDH"; }
        @Override public String getFormat() { return "K04-HYBRID-V1"; }
        @Override public byte[] getEncoded() { return frame(pq.getEncoded(), classicalEncoded(classical)); }
    }

    record HybridPrivateKey(PrivateKey pq, AsymmetricKeyParameter classical, PublicKey pqPublic) implements PrivateKey {
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+XDH"; }
        @Override public String getFormat() { return "K04-HYBRID-V1"; }
        @Override public byte[] getEncoded() {
            byte[] pqBytes = pq.getEncoded();
            byte[] classicalBytes = classicalEncoded(classical);
            try {
                return frame(pqBytes, classicalBytes, pqPublic.getEncoded());
            } finally {
                Arrays.fill(pqBytes, (byte) 0);
                Arrays.fill(classicalBytes, (byte) 0);
            }
        }
    }
}
