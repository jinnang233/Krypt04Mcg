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

    private SignatureCrypto() {}

    static KeyPair generate(SignatureAlgorithm algorithm, SecureRandom random) throws GeneralSecurityException {
        SignatureAlgorithm pqAlgorithm = algorithm.postQuantumComponent();
        var generator = KeyPairGenerator.getInstance(pqAlgorithm.jcaName(), pqAlgorithm.provider());
        generator.initialize(pqAlgorithm.parameterSpec(), random);
        KeyPair pq = generator.generateKeyPair();
        if (!algorithm.customHybrid()) return pq;
        var classicalGenerator = KeyPairGenerator.getInstance(algorithm.classicalAlgorithm(), "BC");
        classicalGenerator.initialize(new EdDSAParameterSpec(algorithm.classicalAlgorithm()), random);
        KeyPair classical = classicalGenerator.generateKeyPair();
        var publicKey = new HybridPublicKey(pq.getPublic(), classical.getPublic());
        return new KeyPair(publicKey, new HybridPrivateKey(pq.getPrivate(), classical.getPrivate(), publicKey));
    }

    static PublicKey decodePublic(SignatureAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PublicKey key;
        if (!algorithm.customHybrid()) {
            key = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider())
                    .generatePublic(new X509EncodedKeySpec(encoded));
        } else {
            byte[][] parts = split(encoded, 2, MAX_KEY_COMPONENT_BYTES);
            PublicKey pq = decodePublic(algorithm.postQuantumComponent(), parts[0]);
            PublicKey classical = KeyFactory.getInstance(algorithm.classicalAlgorithm(), "BC")
                    .generatePublic(new X509EncodedKeySpec(parts[1]));
            key = new HybridPublicKey(pq, classical);
        }
        requireParameters(key, algorithm);
        return key;
    }

    static PrivateKey decodePrivate(SignatureAlgorithm algorithm, byte[] encoded)
            throws GeneralSecurityException, CryptoException {
        PrivateKey key;
        if (!algorithm.customHybrid()) {
            key = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider())
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } else {
            byte[][] parts = split(encoded, 3, MAX_KEY_COMPONENT_BYTES);
            try {
                PrivateKey pq = decodePrivate(algorithm.postQuantumComponent(), parts[0]);
                PrivateKey classical = KeyFactory.getInstance(algorithm.classicalAlgorithm(), "BC")
                        .generatePrivate(new PKCS8EncodedKeySpec(parts[1]));
                var publicKey = (HybridPublicKey) decodePublic(algorithm, parts[2]);
                key = new HybridPrivateKey(pq, classical, publicKey);
            } finally {
                for (byte[] part : parts) Arrays.fill(part, (byte) 0);
            }
        }
        requireParameters(key, algorithm);
        return key;
    }

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

    private static byte[] signComponent(String name, String provider, PrivateKey key, byte[] input, SecureRandom random)
            throws GeneralSecurityException {
        var signature = Signature.getInstance(name, provider);
        signature.initSign(key, random);
        signature.update(input);
        return signature.sign();
    }

    private static boolean verifyComponent(String name, String provider, PublicKey key, byte[] input, byte[] encoded)
            throws GeneralSecurityException {
        var signature = Signature.getInstance(name, provider);
        signature.initVerify(key);
        signature.update(input);
        return signature.verify(encoded);
    }

    // Fixed-size hashes keep signing costs bounded even for multi-megabyte UOV public keys.
    // Domain, exact suite, both public keys and the message are covered by both components.
    private static byte[] context(SignatureAlgorithm algorithm, HybridPublicKey publicKey, byte[] input) {
        return frame(DOMAIN, algorithm.identifier().getBytes(StandardCharsets.UTF_8),
                hash(publicKey.getEncoded()), hash(input));
    }

    private static byte[] hash(byte[] input) {
        var digest = new SHA512Digest();
        digest.update(input, 0, input.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    private static byte[] frame(byte[]... components) {
        int size = 4;
        for (byte[] component : components) size = Math.addExact(size, Math.addExact(4, component.length));
        var buffer = ByteBuffer.allocate(size).putInt(MAGIC);
        for (byte[] component : components) buffer.putInt(component.length).put(component);
        return buffer.array();
    }

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
            for (byte[] part : parts) if (part != null) Arrays.fill(part, (byte) 0);
            throw e;
        }
    }

    record HybridPublicKey(PublicKey pq, PublicKey classical) implements PublicKey {
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+" + classical.getAlgorithm(); }
        @Override public String getFormat() { return "K04-HYBRID-SIGNATURE-V1"; }
        @Override public byte[] getEncoded() { return frame(pq.getEncoded(), classical.getEncoded()); }
    }

    record HybridPrivateKey(PrivateKey pq, PrivateKey classical, HybridPublicKey publicKey) implements PrivateKey {
        @Override public String getAlgorithm() { return pq.getAlgorithm() + "+" + classical.getAlgorithm(); }
        @Override public String getFormat() { return "K04-HYBRID-SIGNATURE-V1"; }
        @Override public byte[] getEncoded() {
            byte[] pqEncoded = pq.getEncoded();
            byte[] classicalEncoded = classical.getEncoded();
            try {
                return frame(pqEncoded, classicalEncoded, publicKey.getEncoded());
            } finally {
                Arrays.fill(pqEncoded, (byte) 0);
                Arrays.fill(classicalEncoded, (byte) 0);
            }
        }
    }
}
