package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.Cipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class CryptoService {
    public static final int MESSAGE_ID_BYTES = 16;
    public static final byte FLAG_SIGNED = 0x01;
    public static final byte FLAG_COMPRESSED = 0x02;
    public static final byte FLAG_SESSION_RESPONSE = 0x04;
    public static final int MAX_PLAINTEXT_BYTES = 64 * 1024;
    private static final int NONCE_BYTES = 12;
    private static final int AEAD_KEY_BYTES = 32;
    private static final int GCM_TAG_BITS = 128;
    private static final String BCPQC = "BCPQC";
    private static final String BC = "BC";

    private final SecureRandom secureRandom;
    private final PacketCodec packetCodec;
    private final int maxPlaintextBytes;

    /**
     * Creates a cryptographic service with registered BC providers, a bounded packet codec and a validated
     * plaintext ceiling. The default constructor keeps chat at 64 KiB; the integer overload permits
     * separately bounded optional-file envelopes. Supplied SecureRandom and codec instances remain the
     * dependencies used by later operations.
     *
     * @param maxPlaintextBytes the maximum accepted plaintext size in bytes
     */
    public CryptoService(int maxPlaintextBytes) {
        this(new SecureRandom(), new PacketCodec(maxPlaintextBytes + 65536), maxPlaintextBytes);
    }

    /**
     * Creates a cryptographic service with registered BC providers, a bounded packet codec and a validated
     * plaintext ceiling. The default constructor keeps chat at 64 KiB; the integer overload permits
     * separately bounded optional-file envelopes. Supplied SecureRandom and codec instances remain the
     * dependencies used by later operations.
     */
    public CryptoService() {
        this(new SecureRandom(), new PacketCodec());
    }

    /**
     * Creates a cryptographic service with registered BC providers, a bounded packet codec and a validated
     * plaintext ceiling. The default constructor keeps chat at 64 KiB; the integer overload permits
     * separately bounded optional-file envelopes. Supplied SecureRandom and codec instances remain the
     * dependencies used by later operations.
     *
     * @param secureRandom the configured cryptographic randomness source
     * @param packetCodec the packet encoding and decoding collaborator
     */
    public CryptoService(SecureRandom secureRandom, PacketCodec packetCodec) {
        this(secureRandom, packetCodec, MAX_PLAINTEXT_BYTES);
    }

    /**
     * Creates a cryptographic service with registered BC providers, a bounded packet codec and a validated
     * plaintext ceiling. The default constructor keeps chat at 64 KiB; the integer overload permits
     * separately bounded optional-file envelopes. Supplied SecureRandom and codec instances remain the
     * dependencies used by later operations.
     *
     * @param secureRandom the configured cryptographic randomness source
     * @param packetCodec the packet encoding and decoding collaborator
     * @param maxPlaintextBytes the maximum accepted plaintext size in bytes
     */
    private CryptoService(SecureRandom secureRandom, PacketCodec packetCodec, int maxPlaintextBytes) {
        if (maxPlaintextBytes < 1 || maxPlaintextBytes > 16 * 1024 * 1024) {
            throw new IllegalArgumentException("Invalid plaintext limit");
        }
        ensureProviders();
        this.secureRandom = secureRandom;
        this.packetCodec = packetCodec;
        this.maxPlaintextBytes = maxPlaintextBytes;
    }

    /**
     * Generates the selected KEM and signature key pairs through their configured providers and records
     * their owner, UUID, encoded key material and fingerprints. Null selections use the explicit project
     * defaults; generation does not establish trust in an externally supplied identity.
     *
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public LocalKeyMaterial generateLocalKeys(String owner, String uuid) throws CryptoException {
        return generateLocalKeys(owner, uuid, KemAlgorithm.ML_KEM_768_X25519, SignatureAlgorithm.MLDSA65_ED25519_SHA512);
    }

    /**
     * Generates the selected KEM and signature key pairs through their configured providers and records
     * their owner, UUID, encoded key material and fingerprints. Null selections use the explicit project
     * defaults; generation does not establish trust in an externally supplied identity.
     *
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @param kemAlgorithm the selected KEM suite
     * @param signatureAlgorithm the selected signature suite
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public LocalKeyMaterial generateLocalKeys(String owner, String uuid, KemAlgorithm kemAlgorithm,
                                              SignatureAlgorithm signatureAlgorithm) throws CryptoException {
        KemAlgorithm selectedKem = kemAlgorithm == null ? KemAlgorithm.ML_KEM_768_X25519 : kemAlgorithm;
        SignatureAlgorithm selectedSignature = signatureAlgorithm == null
                ? SignatureAlgorithm.MLDSA65_ED25519_SHA512 : signatureAlgorithm;
        try {
            KeyPair kem = KemCrypto.generate(selectedKem, secureRandom);

            KeyPair sig = SignatureCrypto.generate(selectedSignature, secureRandom);

            Instant now = Instant.now();
            return new LocalKeyMaterial(
                    keyRecord(selectedKem.identifier() + "/public", owner, uuid, now, kem.getPublic().getEncoded()),
                    keyRecord(selectedKem.identifier() + "/private", owner, uuid, now, kem.getPrivate().getEncoded()),
                    keyRecord(selectedSignature.identifier() + "/public", owner, uuid, now, sig.getPublic().getEncoded()),
                    keyRecord(selectedSignature.identifier() + "/private", owner, uuid, now, sig.getPrivate().getEncoded())
            );
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Unable to generate post-quantum keys", e);
        }
    }

    /**
     * Draws a fresh 16-byte message identifier from the configured SecureRandom. The identifier is used
     * for packet correlation and HKDF salt; it is not an authentication credential.
     *
     * @return the resulting array produced by this operation
     */
    public byte[] randomMessageId() {
        byte[] id = new byte[MESSAGE_ID_BYTES];
        /*
         * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
         * Production randomness must remain unpredictable; a random nonce still depends on avoiding
         * collisions/reuse under its key.
         */
        secureRandom.nextBytes(id);
        return id;
    }

    /**
     * Encrypts a bounded UTF-8 message for the recipient KEM public key and optionally signs the complete
     * packet. Overloads select the documented compression and AEAD defaults. The caller must establish
     * recipient trust before invoking this cryptographic operation.
     *
     * @param receiver the intended recipient associated with this operation
     * @param senderKeys the local sender key material
     * @param sender the sender or source associated with this operation
     * @param message the message supplied to this operation
     * @param sign whether a signature is added to the encrypted packet
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public EncryptedPacket encryptFor(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender, String message, boolean sign)
            throws CryptoException {
        return encryptFor(receiver, senderKeys, sender, message, sign, false);
    }

    /**
     * Encrypts a bounded UTF-8 message for the recipient KEM public key and optionally signs the complete
     * packet. Overloads select the documented compression and AEAD defaults. The caller must establish
     * recipient trust before invoking this cryptographic operation.
     *
     * @param receiver the intended recipient associated with this operation
     * @param senderKeys the local sender key material
     * @param sender the sender or source associated with this operation
     * @param message the message supplied to this operation
     * @param sign whether a signature is added to the encrypted packet
     * @param compress whether the encoded plaintext is compressed before encryption
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public EncryptedPacket encryptFor(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender, String message,
                                      boolean sign, boolean compress)
            throws CryptoException {
        return encryptFor(receiver, senderKeys, sender, message, sign, compress, AeadAlgorithm.AES_256_GCM);
    }

    /**
     * Encrypts a bounded UTF-8 message for the recipient KEM public key and optionally signs the complete
     * packet. Overloads select the documented compression and AEAD defaults. The caller must establish
     * recipient trust before invoking this cryptographic operation.
     *
     * @param receiver the intended recipient associated with this operation
     * @param senderKeys the local sender key material
     * @param sender the sender or source associated with this operation
     * @param message the message supplied to this operation
     * @param sign whether a signature is added to the encrypted packet
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public EncryptedPacket encryptFor(PublicIdentity receiver, LocalKeyMaterial senderKeys, String sender, String message,
                                      boolean sign, boolean compress, AeadAlgorithm aeadAlgorithm)
            throws CryptoException {
        return encryptForKem(receiver.kemPublicKey(), receiver.owner(), senderKeys, sender, message, sign, compress,
                aeadAlgorithm, sign ? PacketType.SIGNED_KEM_MESSAGE : PacketType.KEM_MESSAGE, (byte) 0);
    }

    /**
     * Builds a signed KEM-encrypted handshake envelope and marks whether it is a response. The handshake
     * service is responsible for binding request IDs, fingerprints, predecessor epochs and durable replay
     * state; this method only constructs the cryptographic envelope.
     *
     * @param receiverKem the receiver kem supplied to this operation
     * @param receiver the intended recipient associated with this operation
     * @param senderKeys the local sender key material
     * @param sender the sender or source associated with this operation
     * @param payload the payload supplied to this operation
     * @param response the response supplied to this operation
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public EncryptedPacket encryptSessionExchange(KeyRecord receiverKem, String receiver, LocalKeyMaterial senderKeys,
                                                   String sender, String payload, boolean response, boolean compress,
                                                   AeadAlgorithm aeadAlgorithm) throws CryptoException {
        return encryptForKem(receiverKem, receiver, senderKeys, sender, payload, true, compress, aeadAlgorithm,
                PacketType.SESSION_EXCHANGE, response ? FLAG_SESSION_RESPONSE : 0);
    }

    /**
     * Encodes and bounds plaintext before optional compression, validates the recipient KEM selection, and
     * encapsulates a fresh secret through KemCrypto. HKDF-SHA256 derives a separate AEAD key using the
     * random message ID as salt and a message-specific domain label. A fresh 96-bit nonce protects the
     * AEAD operation; canonical packet metadata is supplied as AAD, and optional signatures cover the
     * canonical signature input including the ciphertext. The temporary derived key is overwritten in
     * finally; Java/provider copies are not guaranteed to be erasable.
     *
     * @param receiverKem the receiver kem supplied to this operation
     * @param receiver the intended recipient associated with this operation
     * @param senderKeys the local sender key material
     * @param sender the sender or source associated with this operation
     * @param message the message supplied to this operation
     * @param sign whether a signature is added to the encrypted packet
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @param packetType the packet type supplied to this operation
     * @param extraFlags the extra flags supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private EncryptedPacket encryptForKem(KeyRecord receiverKem, String receiver, LocalKeyMaterial senderKeys,
                                          String sender, String message, boolean sign, boolean compress,
                                          AeadAlgorithm aeadAlgorithm, PacketType packetType, byte extraFlags)
            throws CryptoException {
        byte[] plaintext = encodePlaintext(message);
        KemAlgorithm kemAlgorithm = kemAlgorithm(receiverKem);
        SignatureAlgorithm signatureAlgorithm = sign
                ? signatureAlgorithm(senderKeys == null ? null : senderKeys.signaturePrivateKey()) : null;
        AeadAlgorithm selectedAead = aeadAlgorithm == null ? AeadAlgorithm.AES_256_GCM : aeadAlgorithm;
        byte[] derivedKey = null;
        try {
            byte[] messageId = randomMessageId();
            PublicKey kemPublic = KemCrypto.decodePublic(kemAlgorithm, Base64Url.decode(receiverKem.keyData()));
            requireRole(receiverKem.algorithm(), "/public");
            SecretKeyWithEncapsulation kemSecret = KemCrypto.encapsulate(kemAlgorithm, kemPublic, secureRandom);
            byte[] encapsulation = kemSecret.getEncapsulation();
            derivedKey = deriveMessageKey(kemSecret, messageId);
            byte[] nonce = randomNonce();
            byte flags = (byte) ((sign ? FLAG_SIGNED : 0) | (compress ? FLAG_COMPRESSED : 0) | extraFlags);
            byte[] payload = compress ? deflate(plaintext) : plaintext;

            EncryptedPacket packetTemplate = new EncryptedPacket(EncryptedPacket.VERSION,
                    packetType, flags, sender, receiver, System.currentTimeMillis(), messageId,
                    (short) 0, (short) 1, sign
                    ? AlgorithmSuite.of(kemAlgorithm, signatureAlgorithm, selectedAead)
                    : new AlgorithmSuite(kemAlgorithm.identifier(), "NONE", selectedAead.identifier(),
                    AlgorithmSuite.HKDF_SHA256),
                    nonce, encapsulation, new byte[0], new byte[0]);

            byte[] ciphertext = aeadEncrypt(selectedAead, derivedKey, nonce, packetCodec.aadFor(packetTemplate), payload);
            EncryptedPacket unsigned = new EncryptedPacket(packetTemplate.protocolVersion(), packetTemplate.type(), packetTemplate.flags(),
                    packetTemplate.sender(), packetTemplate.receiver(), packetTemplate.timestampMillis(), packetTemplate.messageId(),
                    packetTemplate.aadFragmentIndex(), packetTemplate.aadFragmentTotal(), packetTemplate.algorithms(), nonce,
                    encapsulation, ciphertext, new byte[0]);
            byte[] signature = sign ? sign(senderKeys.signaturePrivateKey(), packetCodec.signatureInput(unsigned)) : new byte[0];
            return new EncryptedPacket(unsigned.protocolVersion(), unsigned.type(), unsigned.flags(), unsigned.sender(),
                    unsigned.receiver(), unsigned.timestampMillis(), unsigned.messageId(), unsigned.aadFragmentIndex(),
                    unsigned.aadFragmentTotal(), unsigned.algorithms(), unsigned.nonce(), unsigned.kemCiphertext(),
                    unsigned.ciphertext(), signature);
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to encrypt message", e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            if (derivedKey != null) Arrays.fill(derivedKey, (byte) 0);
        }
    }

    /**
     * Encrypts a session message using a per-message HKDF key derived from the 32-byte session secret and
     * fresh message ID. Validated session ID and sequence are bound into versioned packet metadata and
     * AEAD AAD. This method does not advance durable session counters; the session service must reserve or
     * commit them separately.
     *
     * @param receiver the intended recipient associated with this operation
     * @param sender the sender or source associated with this operation
     * @param sessionSecret the shared secret for the expected session epoch
     * @param sessionId the identifier of the expected session epoch
     * @param sequence the record or control sequence in the relevant replay domain
     * @param message the message supplied to this operation
     * @param compress whether the encoded plaintext is compressed before encryption
     * @param aeadAlgorithm the selected authenticated-encryption suite
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public EncryptedPacket encryptWithSession(String receiver, String sender, byte[] sessionSecret,
                                              String sessionId, long sequence, String message, boolean compress,
                                              AeadAlgorithm aeadAlgorithm) throws CryptoException {
        byte[] plaintext = encodePlaintext(message);
        validateSessionMetadata(sessionId, sequence);
        AeadAlgorithm selectedAead = aeadAlgorithm == null ? AeadAlgorithm.AES_256_GCM : aeadAlgorithm;
        byte[] derivedKey = null;
        try {
            byte[] messageId = randomMessageId();
            derivedKey = deriveSessionSecret(sessionSecret, messageId);
            byte[] nonce = randomNonce();
            byte flags = compress ? FLAG_COMPRESSED : 0;
            EncryptedPacket template = new EncryptedPacket(EncryptedPacket.VERSION, PacketType.SESSION_MESSAGE,
                    flags, sender, receiver, System.currentTimeMillis(), messageId, (short) 0, (short) 1,
                    new AlgorithmSuite("NONE", "NONE", selectedAead.identifier(), AlgorithmSuite.HKDF_SHA256),
                    nonce, new byte[0], new byte[0], new byte[0], sessionId, sequence);
            byte[] ciphertext = aeadEncrypt(selectedAead, derivedKey, nonce, packetCodec.aadFor(template),
                    compress ? deflate(plaintext) : plaintext);
            return new EncryptedPacket(template.protocolVersion(), template.type(), flags, sender, receiver,
                    template.timestampMillis(), messageId, (short) 0, (short) 1, template.algorithms(), nonce,
                    new byte[0], ciphertext, new byte[0], sessionId, sequence);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to encrypt session message", e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            if (derivedKey != null) Arrays.fill(derivedKey, (byte) 0);
        }
    }

    /**
     * Validates packet structure, recipient identity and the declared KEM against local private-key
     * parameters before decapsulation. Signed packets must match the supplied sender identity and verify
     * before AEAD plaintext is exposed. Transport identity, trust decisions, freshness and persistent
     * replay admission belong to higher-level receive handlers.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param receiverKeys the local recipient key material
     * @param claimedSender the public identity to compare with authenticated sender metadata
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public String decrypt(EncryptedPacket packet, LocalKeyMaterial receiverKeys, PublicIdentity claimedSender)
            throws CryptoException {
        validateProtocol(packet);
        if (!packet.receiver().equalsIgnoreCase(receiverKeys.kemPublicKey().owner())) {
            throw new CryptoException("Packet receiver mismatch: expected " + receiverKeys.kemPublicKey().owner() + ", got " + packet.receiver());
        }
        KemAlgorithm packetKem = kemAlgorithm(packet.algorithms().kem());
        requireSameAlgorithm("KEM", packetKem.identifier(), kemAlgorithm(receiverKeys.kemPrivateKey()).identifier());
        try {
            PrivateKey privateKey = decodeKemPrivateKey(packetKem, receiverKeys.kemPrivateKey().keyData());
            requireRole(receiverKeys.kemPrivateKey().algorithm(), "/private");
            KemCrypto.requireParameters(privateKey, packetKem);
            return decryptKemPacket(packet, receiverKeys.kemPublicKey().owner(), packetKem, privateKey, claimedSender);
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to decrypt message", e);
        }
    }

    /**
     * Decrypts only a flagged handshake response with the matching pending ephemeral KEM key pair. A
     * copied private-key encoding is overwritten after decoding, and normal signature, recipient and AEAD
     * checks still apply. The handshake service separately validates correlation fields and commits the
     * resulting session.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param receiver the intended recipient associated with this operation
     * @param ephemeralKeyPair the ephemeral key pair supplied to this operation
     * @param claimedSender the public identity to compare with authenticated sender metadata
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public String decryptSessionExchangeResponse(EncryptedPacket packet, String receiver,
                                                 EphemeralKemKeyPair ephemeralKeyPair,
                                                 PublicIdentity claimedSender) throws CryptoException {
        validateProtocol(packet);
        if (packet.type() != PacketType.SESSION_EXCHANGE
                || (packet.flags() & FLAG_SESSION_RESPONSE) == 0) {
            throw new CryptoException("Packet is not a session exchange response");
        }
        KemAlgorithm packetKem = kemAlgorithm(packet.algorithms().kem());
        requireSameAlgorithm("ephemeral KEM", packetKem.identifier(), ephemeralKeyPair.algorithm().identifier());
        try {
            PrivateKey privateKey;
            byte[] encoded = ephemeralKeyPair.privateKey();
            try {
                privateKey = KemCrypto.decodePrivate(packetKem, encoded);
            } finally {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(encoded, (byte) 0);
            }
            KemCrypto.requireParameters(privateKey, packetKem);
            return decryptKemPacket(packet, receiver, packetKem, privateKey, claimedSender);
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to decrypt session exchange response", e);
        }
    }

    /**
     * Requires recipient and signed-sender identity consistency, validates the declared algorithms, and
     * verifies the canonical signature before KEM decapsulation. AEAD verifies the tag with canonical AAD
     * before plaintext decoding or bounded inflation. Unsigned KEM encryption authenticates ciphertext
     * integrity under the derived key but does not prove a named sender. Derived-key buffers are
     * overwritten on both success and failure.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param receiver the intended recipient associated with this operation
     * @param packetKem the packet kem supplied to this operation
     * @param privateKey the private key material used by the selected primitive
     * @param claimedSender the public identity to compare with authenticated sender metadata
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private String decryptKemPacket(EncryptedPacket packet, String receiver, KemAlgorithm packetKem,
                                    PrivateKey privateKey, PublicIdentity claimedSender) throws CryptoException {
        if (!packet.receiver().equalsIgnoreCase(receiver)) {
            throw new CryptoException("Packet receiver mismatch: expected " + receiver + ", got " + packet.receiver());
        }
        if (packet.signed() && (claimedSender == null
                || !packet.sender().equalsIgnoreCase(claimedSender.owner())
                || claimedSender.signaturePublicKey() == null
                || !packet.sender().equalsIgnoreCase(claimedSender.signaturePublicKey().owner()))) {
            throw new CryptoException("Signature identity does not match packet sender");
        }
        SignatureAlgorithm packetSignature = packet.signed()
                ? signatureAlgorithm(packet.algorithms().signature()) : null;
        AeadAlgorithm packetAead = aeadAlgorithm(packet.algorithms().aead());
        validateHkdf(packet.algorithms().hkdf());
        byte[] derivedKey = null;
        try {
            if (packet.signed()) {
                requireSameAlgorithm("signature", packetSignature.identifier(),
                        signatureAlgorithm(claimedSender.signaturePublicKey()).identifier());
                EncryptedPacket unsigned = packetCodec.withoutSignature(packet);
                boolean valid = verify(packetSignature, claimedSender.signaturePublicKey(),
                        packetCodec.signatureInput(unsigned), packet.signature());
                if (!valid) {
                    throw new CryptoException("Signature verification failed for " + packet.sender());
                }
            }
            SecretKeyWithEncapsulation kemSecret = KemCrypto.extract(packetKem, privateKey, packet.kemCiphertext());
            derivedKey = deriveMessageKey(kemSecret, packet.messageId());
            byte[] plaintext = aeadDecrypt(packetAead, derivedKey, packet.nonce(), packetCodec.aadFor(packet),
                    packet.ciphertext());
            byte[] payload = (packet.flags() & FLAG_COMPRESSED) != 0 ? inflate(plaintext) : plaintext;
            return decodePlaintext(payload);
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to decrypt message", e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            if (derivedKey != null) Arrays.fill(derivedKey, (byte) 0);
        }
    }

    /**
     * Checks the expected sender, recipient, session epoch and exact sequence before deriving the message
     * key and authenticating AEAD ciphertext. The supplied sequence is an expected value, not a replay
     * cache update. Only authenticated plaintext is decoded or inflated; callers must durably advance
     * receive counters after acceptance.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @param receiver the intended recipient associated with this operation
     * @param sender the sender or source associated with this operation
     * @param sessionSecret the shared secret for the expected session epoch
     * @param sessionId the identifier of the expected session epoch
     * @param sequence the record or control sequence in the relevant replay domain
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public String decryptWithSession(EncryptedPacket packet, String receiver, String sender,
                                     byte[] sessionSecret, String sessionId, long sequence) throws CryptoException {
        validateProtocol(packet);
        if (!packet.receiver().equalsIgnoreCase(receiver)) {
            throw new CryptoException("Packet receiver mismatch: expected " + receiver + ", got " + packet.receiver());
        }
        if (packet.type() != PacketType.SESSION_MESSAGE) {
            throw new CryptoException("Packet is not a session message: " + packet.type());
        }
        if (!packet.sender().equalsIgnoreCase(sender) || !packet.sessionId().equals(sessionId)
                || packet.sequence() != sequence) {
            throw new CryptoException("Session identity, epoch or sequence mismatch");
        }
        AeadAlgorithm packetAead = aeadAlgorithm(packet.algorithms().aead());
        validateHkdf(packet.algorithms().hkdf());
        byte[] derivedKey = null;
        try {
            derivedKey = deriveSessionSecret(sessionSecret, packet.messageId());
            byte[] plaintext = aeadDecrypt(packetAead, derivedKey, packet.nonce(), packetCodec.aadFor(packet),
                    packet.ciphertext());
            byte[] payload = (packet.flags() & FLAG_COMPRESSED) != 0 ? inflate(plaintext) : plaintext;
            return decodePlaintext(payload);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Unable to decrypt session message", e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            if (derivedKey != null) Arrays.fill(derivedKey, (byte) 0);
        }
    }

    /**
     * Signs the supplied canonical bytes with a private key whose recorded role and selected parameters
     * are checked. SignatureCrypto dispatches native provider suites or the project hybrid format; signing
     * alone does not validate packet routing or establish peer trust.
     *
     * @param privateKeyRecord the private key record supplied to this operation
     * @param input the input bytes or stream consumed by the operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public byte[] sign(KeyRecord privateKeyRecord, byte[] input) throws CryptoException {
        return sign(signatureAlgorithm(privateKeyRecord), privateKeyRecord, input);
    }

    /**
     * Signs the supplied canonical bytes with a private key whose recorded role and selected parameters
     * are checked. SignatureCrypto dispatches native provider suites or the project hybrid format; signing
     * alone does not validate packet routing or establish peer trust.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param privateKeyRecord the private key record supplied to this operation
     * @param input the input bytes or stream consumed by the operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private byte[] sign(SignatureAlgorithm algorithm, KeyRecord privateKeyRecord, byte[] input)
            throws CryptoException {
        try {
            requireRole(privateKeyRecord.algorithm(), "/private");
            PrivateKey key = decodeSignaturePrivateKey(algorithm, privateKeyRecord.keyData());
            return SignatureCrypto.sign(algorithm, key, input, secureRandom);
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to sign packet", e);
        }
    }

    /**
     * Verifies supplied bytes and signature against a role-checked public-key record and exact selected
     * parameters. Hybrid suites require both components. A valid signature authenticates those bytes under
     * that key; trust in the owner and freshness of the message require separate checks.
     *
     * @param publicKeyRecord the public key record supplied to this operation
     * @param input the input bytes or stream consumed by the operation
     * @param signatureBytes the signature bytes to verify
     * @return whether the condition or operation described above succeeds
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public boolean verify(KeyRecord publicKeyRecord, byte[] input, byte[] signatureBytes) throws CryptoException {
        return verify(signatureAlgorithm(publicKeyRecord), publicKeyRecord, input, signatureBytes);
    }

    /**
     * Verifies supplied bytes and signature against a role-checked public-key record and exact selected
     * parameters. Hybrid suites require both components. A valid signature authenticates those bytes under
     * that key; trust in the owner and freshness of the message require separate checks.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param publicKeyRecord the public key record supplied to this operation
     * @param input the input bytes or stream consumed by the operation
     * @param signatureBytes the signature bytes to verify
     * @return whether the condition or operation described above succeeds
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private boolean verify(SignatureAlgorithm algorithm, KeyRecord publicKeyRecord, byte[] input,
                           byte[] signatureBytes) throws CryptoException {
        try {
            requireRole(publicKeyRecord.algorithm(), "/public");
            PublicKey key = SignatureCrypto.decodePublic(algorithm, Base64Url.decode(publicKeyRecord.keyData()));
            return SignatureCrypto.verify(algorithm, key, input, signatureBytes);
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to verify packet signature", e);
        }
    }

    /**
     * Derives a 32-byte API session secret from exactly 32 bytes of session material and a 16-byte session
     * ID using HKDF-SHA256 and the data-session domain label. The label separates API keys from chat keys;
     * HKDF itself does not authenticate the session exchange.
     *
     * @param secret the shared secret used as key-derivation input
     * @param sessionId the identifier of the expected session epoch
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public byte[] deriveDataSessionSecret(byte[] secret, byte[] sessionId) throws CryptoException {
        if (secret == null || sessionId == null || secret.length != AEAD_KEY_BYTES || sessionId.length != MESSAGE_ID_BYTES)
            throw new CryptoException("Invalid API session key material");
        return hkdf(secret, sessionId, "krypt04mcg data session v1".getBytes(StandardCharsets.UTF_8), AEAD_KEY_BYTES);
    }

    /**
     * Derives a 32-byte chat-session message key from a validated 32-byte secret and 16-byte message ID
     * with HKDF-SHA256 and the chat-session label. Fresh message IDs prevent deliberate reuse of this key
     * derivation context; session sequence validation is handled separately.
     *
     * @param secret the shared secret used as key-derivation input
     * @param messageId the message identifier used for correlation or key-derivation context
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public byte[] deriveSessionSecret(byte[] secret, byte[] messageId) throws CryptoException {
        if (secret == null || secret.length != AEAD_KEY_BYTES) {
            throw new CryptoException("Session secret must contain 32 bytes");
        }
        if (messageId == null || messageId.length != MESSAGE_ID_BYTES) {
            throw new CryptoException("Session message ID must contain 16 bytes");
        }
        return hkdf(secret, messageId, "krypt04mcg session".getBytes(StandardCharsets.UTF_8), AEAD_KEY_BYTES);
    }

    /**
     * Hashes the supplied encoded key bytes with SHA-256 and returns the full hexadecimal digest.
     * Public-key fingerprints are identity-comparison values, not encryption or a replacement for
     * verification over a trusted external channel; hashing does not make private bytes safe to disclose.
     *
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public String fingerprint(byte[] encoded) throws CryptoException {
        try {
            /*
             * Delegates the requested digest to JCA for canonical fingerprint or context binding. A plain digest
             * is not a MAC or signature and cannot independently establish trust, freshness or secrecy of
             * low-entropy input.
             */
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            return Hex.encode(digest);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Unable to fingerprint key", e);
        }
    }

    /**
     * Generates temporary KEM key material for a pending session exchange and wraps encoded copies in a
     * closeable holder. The handshake lifecycle is responsible for closing that holder after completion,
     * expiry or cancellation.
     *
     * @param selectedAlgorithm the selected algorithm supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public EphemeralKemKeyPair generateEphemeralKemKeyPair(KemAlgorithm selectedAlgorithm) throws CryptoException {
        KemAlgorithm algorithm = selectedAlgorithm == null ? KemAlgorithm.ML_KEM_768_X25519 : selectedAlgorithm;
        try {
            KeyPair pair = KemCrypto.generate(algorithm, secureRandom);
            byte[] privateBytes = pair.getPrivate().getEncoded();
            try {
                return new EphemeralKemKeyPair(algorithm, pair.getPublic().getEncoded(), privateBytes);
            } finally {
                /*
                 * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
                 * immutable Strings, returned copies and provider/native key objects may retain other copies.
                 */
                Arrays.fill(privateBytes, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Unable to generate ephemeral KEM key", e);
        }
    }

    /**
     * Constructs and validates an imported ephemeral KEM public record against its declared algorithm,
     * parameter set, owner and UUID. Structural validation cannot independently establish whether a remote
     * player should be trusted.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @param keyData the key data supplied to this operation
     * @param createdAt the created at supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public KeyRecord validateEphemeralKemPublicKey(String algorithm, String owner, String uuid, String keyData,
                                                    Instant createdAt) throws CryptoException {
        return validatePublicRecord(new KeyRecord(algorithm + "/public", owner, uuid, "", createdAt, keyData),
                owner, uuid, true);
    }

    /**
     * Performs the key record operation for the packet cryptography service.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @param createdAt the created at supplied to this operation
     * @param encoded the encoded bytes to parse or verify
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public KeyRecord keyRecord(String algorithm, String owner, String uuid, Instant createdAt, byte[] encoded) throws CryptoException {
        return new KeyRecord(algorithm, owner, uuid, fingerprint(encoded), createdAt, Base64Url.encode(encoded));
    }

    /**
     * Validates both imported public-key records, their roles, parameters, metadata and fingerprints as
     * one identity. Provider decoding rejects incompatible encodings and parameter substitution; user
     * verification of the complete identity remains a separate trust decision.
     *
     * @param identity the identity supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public PublicIdentity validatePublicIdentity(PublicIdentity identity) throws CryptoException {
        if (identity == null || isBlank(identity.owner()) || isBlank(identity.uuid())) {
            throw new CryptoException("Public identity owner or UUID is missing");
        }
        KeyRecord kem = validatePublicRecord(identity.kemPublicKey(), identity.owner(), identity.uuid(), true);
        KeyRecord signature = validatePublicRecord(identity.signaturePublicKey(), identity.owner(), identity.uuid(), false);
        return new PublicIdentity(identity.owner(), identity.uuid(), kem, signature);
    }

    /**
     * Validates local public/private roles and identity metadata and checks that each private key
     * corresponds to its public key. Pair testing detects inconsistent stored material; it does not
     * replace storage access controls.
     *
     * @param material the material supplied to this operation
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    public LocalKeyMaterial validateLocalKeyMaterial(LocalKeyMaterial material, String owner, String uuid)
            throws CryptoException {
        if (material == null || isBlank(owner) || isBlank(uuid)) {
            throw new CryptoException("Local key identity is missing");
        }
        KeyRecord kemPublic = validatePublicRecord(material.kemPublicKey(), owner, uuid, true);
        KeyRecord kemPrivate = validatePrivateRecord(material.kemPrivateKey(), owner, uuid, true);
        KeyRecord signaturePublic = validatePublicRecord(material.signaturePublicKey(), owner, uuid, false);
        KeyRecord signaturePrivate = validatePrivateRecord(material.signaturePrivateKey(), owner, uuid, false);
        requireSameAlgorithm("KEM", KemAlgorithm.fromIdentifier(kemPublic.algorithm()).identifier(),
                KemAlgorithm.fromIdentifier(kemPrivate.algorithm()).identifier());
        requireSameAlgorithm("signature", SignatureAlgorithm.fromIdentifier(signaturePublic.algorithm()).identifier(),
                SignatureAlgorithm.fromIdentifier(signaturePrivate.algorithm()).identifier());
        verifyLocalKeyPairs(kemPublic, kemPrivate, signaturePublic, signaturePrivate);
        return new LocalKeyMaterial(kemPublic, kemPrivate, signaturePublic, signaturePrivate);
    }

    /**
     * Decodes the declared public-key suite, checks exact parameters and recomputes the fingerprint over
     * the encoded bytes. Metadata and public role are validated before the record is accepted.
     *
     * @param record the record supplied to this operation
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @param kem the kem supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private KeyRecord validatePublicRecord(KeyRecord record, String owner, String uuid, boolean kem)
            throws CryptoException {
        validateRecordIdentity(record, owner, uuid);
        requireRole(record.algorithm(), "/public");
        try {
            String identifier;
            PublicKey decoded;
            if (kem) {
                KemAlgorithm algorithm = KemAlgorithm.fromIdentifier(record.algorithm());
                identifier = algorithm.identifier();
                decoded = KemCrypto.decodePublic(algorithm, Base64Url.decode(record.keyData()));
            } else {
                SignatureAlgorithm algorithm = SignatureAlgorithm.fromIdentifier(record.algorithm());
                identifier = algorithm.identifier();
                decoded = SignatureCrypto.decodePublic(algorithm, Base64Url.decode(record.keyData()));
            }
            return keyRecord(identifier + "/public", owner, uuid, record.createdAt(), decoded.getEncoded());
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Invalid " + (kem ? "KEM" : "signature") + " public key", e);
        }
    }

    /**
     * Decodes a private-key record using its declared suite and checks its role, identity metadata and
     * parameters. Encoded private-key copies are handled by the decoding helpers and must not be logged.
     *
     * @param record the record supplied to this operation
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @param kem the kem supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private KeyRecord validatePrivateRecord(KeyRecord record, String owner, String uuid, boolean kem)
            throws CryptoException {
        validateRecordIdentity(record, owner, uuid);
        requireRole(record.algorithm(), "/private");
        try {
            String identifier;
            PrivateKey decoded;
            if (kem) {
                KemAlgorithm algorithm = KemAlgorithm.fromIdentifier(record.algorithm());
                identifier = algorithm.identifier();
                decoded = decodeKemPrivateKey(algorithm, record.keyData());
            } else {
                SignatureAlgorithm algorithm = SignatureAlgorithm.fromIdentifier(record.algorithm());
                identifier = algorithm.identifier();
                decoded = decodeSignaturePrivateKey(algorithm, record.keyData());
            }
            return keyRecord(identifier + "/private", owner, uuid, record.createdAt(), decoded.getEncoded());
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Invalid " + (kem ? "KEM" : "signature") + " private key", e);
        }
    }

    /**
     * Checks that a decoded signature key uses the parameter set declared by the selected suite, including
     * the supported composite forms. An algorithm family name alone is insufficient to prevent parameter
     * substitution.
     *
     * @param key the cryptographic key material for this operation
     * @param algorithm the selected algorithm and parameter-set definition
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static void requireSignatureKeyParameters(java.security.Key key, SignatureAlgorithm algorithm)
            throws CryptoException {
        if (!algorithm.nativeHybrid()) {
            requireKeyParameters(key, algorithm.parameterSpec());
            return;
        }
        var identifier = switch (key) {
            case org.bouncycastle.jcajce.CompositePublicKey k -> k.getAlgorithmIdentifier();
            case org.bouncycastle.jcajce.CompositePrivateKey k -> k.getAlgorithmIdentifier();
            default -> throw new CryptoException("Expected BC composite signature key");
        };
        String actual = org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex
                .getAlgorithmName(identifier.getAlgorithm());
        if (!algorithm.jcaName().equals(actual)) {
            throw new CryptoException("Composite signature key does not match the declared algorithm");
        }
    }

    // Generic JCA key factories accept multiple parameter sets. The record label must match
    // the parameters in the decoded key, including for an ephemeral handshake key.
    /**
     * Compares the actual decoded key parameter specification with the expected specification. Unsupported
     * key/specification types and mismatched parameter names fail closed rather than silently selecting a
     * fallback suite.
     *
     * @param key the cryptographic key material for this operation
     * @param expected the expected supplied to this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    static void requireKeyParameters(java.security.Key key,
                                             java.security.spec.AlgorithmParameterSpec expected) throws CryptoException {
        java.security.spec.AlgorithmParameterSpec actual = switch (key) {
            case org.bouncycastle.jcajce.interfaces.MLKEMKey k -> k.getParameterSpec();
            case org.bouncycastle.jcajce.interfaces.CMCEKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.HQCKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.NTRULPRimeKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.SNTRUPrimeKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.MayoKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.HaetaeKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.UOVKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.QRUOVKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.AIMerKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.FaestKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.MQOMKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.SDitHKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.FalconKey k -> k.getParameterSpec();
            case org.bouncycastle.jcajce.interfaces.MLDSAKey k -> k.getParameterSpec();
            case org.bouncycastle.jcajce.interfaces.SLHDSAKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.SQIsignKey k -> k.getParameterSpec();
            case org.bouncycastle.pqc.jcajce.interfaces.SnovaKey k -> k.getParameterSpec();
            default -> throw new CryptoException("Unsupported decoded key type");
        };
        if (actual == null || actual.getClass() != expected.getClass()
                || !parameterName(actual).equalsIgnoreCase(parameterName(expected))) {
            throw new CryptoException("Encoded key parameters do not match the declared algorithm");
        }
    }

    /**
     * Performs the parameter name operation for the packet cryptography service.
     *
     * @param spec the spec supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static String parameterName(java.security.spec.AlgorithmParameterSpec spec) throws CryptoException {
        return switch (spec) {
            case org.bouncycastle.jcajce.spec.MLKEMParameterSpec p -> p.getName();
            case org.bouncycastle.jcajce.spec.CMCEParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec p -> p.getName();
            case org.bouncycastle.jcajce.spec.MLDSAParameterSpec p -> p.getName();
            case org.bouncycastle.jcajce.spec.SLHDSAParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec p -> p.getName();
            case org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec p -> p.getName();
            default -> throw new CryptoException("Unsupported key parameter type");
        };
    }

    /**
     * Exercises KEM encapsulation/decapsulation and signature sign/verify to detect mismatched local
     * public/private pairs. This is a consistency check performed through the selected providers, not a
     * proof of key-generation entropy or an independent cryptographic audit.
     *
     * @param kemPublic the kem public supplied to this operation
     * @param kemPrivate the kem private supplied to this operation
     * @param signaturePublic the signature public supplied to this operation
     * @param signaturePrivate the signature private supplied to this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private void verifyLocalKeyPairs(KeyRecord kemPublic, KeyRecord kemPrivate, KeyRecord signaturePublic,
                                     KeyRecord signaturePrivate) throws CryptoException {
        byte[] challenge = new byte[32];
        /*
         * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
         * Production randomness must remain unpredictable; a random nonce still depends on avoiding
         * collisions/reuse under its key.
         */
        secureRandom.nextBytes(challenge);
        byte[] signature = sign(signaturePrivate, challenge);
        if (!verify(signaturePublic, challenge, signature)) {
            throw new CryptoException("Local signature public and private keys do not match");
        }
        KemAlgorithm algorithm = kemAlgorithm(kemPublic);
        try {
            PublicKey publicKey = KemCrypto.decodePublic(algorithm, Base64Url.decode(kemPublic.keyData()));
            PrivateKey privateKey = decodeKemPrivateKey(algorithm, kemPrivate.keyData());
            SecretKeyWithEncapsulation generated = KemCrypto.encapsulate(algorithm, publicKey, secureRandom);
            SecretKeyWithEncapsulation extracted = KemCrypto.extract(algorithm, privateKey, generated.getEncapsulation());
            /*
             * Compares digest/tag bytes with the JDK authentication-oriented byte comparison rather than
             * converting them to Strings. Equality still depends on the supplied key/context and does not replace
             * identity or replay checks.
             */
            if (!MessageDigest.isEqual(generated.getEncoded(), extracted.getEncoded())) {
                throw new CryptoException("Local KEM public and private keys do not match");
            }
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            throw new CryptoException("Unable to validate local KEM key pair", e);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(challenge, (byte) 0);
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(signature, (byte) 0);
        }
    }

    /**
     * Checks the record identity required by the packet cryptography service and rejects invalid state
     * instead of continuing.
     *
     * @param record the record supplied to this operation
     * @param owner the owner identifier associated with the stored key records
     * @param uuid the identity UUID associated with the key records
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static void validateRecordIdentity(KeyRecord record, String owner, String uuid) throws CryptoException {
        if (record == null || isBlank(record.algorithm()) || isBlank(record.owner()) || isBlank(record.uuid())
                || record.createdAt() == null || isBlank(record.keyData())) {
            throw new CryptoException("Key record is incomplete");
        }
        if (!record.owner().equalsIgnoreCase(owner) || !record.uuid().equalsIgnoreCase(uuid)) {
            throw new CryptoException("Key record identity does not match its containing identity");
        }
    }

    /**
     * Checks the role required by the packet cryptography service and rejects invalid state instead of
     * continuing.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param role the role supplied to this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static void requireRole(String algorithm, String role) throws CryptoException {
        if (algorithm == null || !algorithm.toLowerCase(java.util.Locale.ROOT).endsWith(role)) {
            throw new CryptoException("Key algorithm has the wrong role: " + algorithm);
        }
    }

    /**
     * Reports whether blank holds for the packet cryptography service.
     *
     * @param value the value supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Registers the Bouncy Castle general and post-quantum providers only when missing. Provider
     * registration makes implementations available; suite selection and parameter checks still occur at
     * each cryptographic boundary.
     */
    private static void ensureProviders() {
        if (Security.getProvider(BCPQC) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Draws a fresh 12-byte nonce from SecureRandom for message AEAD operations. Nonce uniqueness under a
     * reused key is essential; this helper relies on random generation rather than a persisted counter.
     *
     * @return the resulting array produced by this operation
     */
    private byte[] randomNonce() {
        byte[] nonce = new byte[NONCE_BYTES];
        /*
         * Draws security-sensitive bytes from the configured SecureRandom rather than a general-purpose PRNG.
         * Production randomness must remain unpredictable; a random nonce still depends on avoiding
         * collisions/reuse under its key.
         */
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    /**
     * Checks the plaintext size required by the packet cryptography service and rejects invalid state
     * instead of continuing.
     *
     * @param plaintext the plaintext bytes to encrypt or process
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private void ensurePlaintextSize(byte[] plaintext) throws CryptoException {
        if (plaintext.length > maxPlaintextBytes) {
            throw new CryptoException("Plaintext message is too large: " + plaintext.length);
        }
    }

    /**
     * Strictly encodes the message as UTF-8 and enforces the configured plaintext-byte limit before
     * compression. Rejecting malformed Unicode avoids different byte representations entering signatures
     * or authenticated payloads.
     *
     * @param message the message supplied to this operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private byte[] encodePlaintext(String message) throws CryptoException {
        if (message == null) {
            throw new CryptoException("Plaintext message is missing");
        }
        // UTF-8 needs at least as many bytes as valid UTF-16 needs code units.
        // Reject huge strings before allocating their encoded form or performing KEM work.
        if (message.length() > maxPlaintextBytes) {
            throw new CryptoException("Plaintext message is too large");
        }
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(message));
            if (encoded.remaining() > maxPlaintextBytes) {
                throw new CryptoException("Plaintext message is too large");
            }
            byte[] plaintext = new byte[encoded.remaining()];
            encoded.get(plaintext);
            return plaintext;
        } catch (CharacterCodingException e) {
            throw new CryptoException("Plaintext message contains invalid Unicode", e);
        }
    }

    /**
     * Strictly decodes bounded UTF-8 plaintext after cryptographic authentication. Malformed or unmappable
     * input is rejected rather than replaced with characters that could hide a wire-level mismatch.
     *
     * @param plaintext the plaintext bytes to encrypt or process
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private String decodePlaintext(byte[] plaintext) throws CryptoException {
        ensurePlaintextSize(plaintext);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plaintext)).toString();
        } catch (CharacterCodingException e) {
            throw new CryptoException("Plaintext message is not valid UTF-8", e);
        }
    }

    /**
     * Checks protocol version, type, flags, required fields, nonce and ciphertext layout before
     * cryptographic work. Compression allowances bound inputs, while PacketCodec validates
     * version-specific field combinations. These structural checks are not signature, trust, freshness or
     * replay validation.
     *
     * @param packet the packet being serialized, authenticated or processed
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private void validateProtocol(EncryptedPacket packet) throws CryptoException {
        if (packet == null || packet.type() == null || packet.ciphertext() == null
                || packet.ciphertext().length < GCM_TAG_BITS / 8
                || packet.kemCiphertext() == null) {
            throw new CryptoException("Packet type or ciphertext is missing or invalid");
        }
        // Include a conservative DEFLATE expansion allowance and the AEAD tag.
        // Bound work before signature verification, KEM extraction or AEAD allocation.
        int maxPayloadBytes = (packet.flags() & FLAG_COMPRESSED) == 0 ? maxPlaintextBytes
                : maxPlaintextBytes + (maxPlaintextBytes + 7) / 8 + (maxPlaintextBytes + 63) / 64 + 64;
        if (packet.ciphertext().length > maxPayloadBytes + GCM_TAG_BITS / 8) {
            throw new CryptoException("Ciphertext exceeds the configured message limit");
        }
        if (packet.protocolVersion() != EncryptedPacket.LEGACY_VERSION
                && packet.protocolVersion() != EncryptedPacket.PREVIOUS_VERSION
                && packet.protocolVersion() != EncryptedPacket.COMPACT_VERSION
                && packet.protocolVersion() != EncryptedPacket.VERSION) {
            throw new CryptoException("Unsupported protocol version: " + Byte.toUnsignedInt(packet.protocolVersion()));
        }
        if (packet.algorithms() == null) {
            throw new CryptoException("Packet algorithm suite is missing");
        }
        try {
            PacketCodec.validateLayout(packet);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid packet layout", e);
        }
        // Before v3, only a signature binds the timestamp. Accepting unsigned legacy
        // packets would let a relay refresh old ciphertext's apparent creation time.
        if (packet.protocolVersion() < EncryptedPacket.COMPACT_VERSION && !packet.signed()) {
            throw new CryptoException("Unsigned legacy packets do not authenticate their timestamp");
        }
        if (packet.sender() == null || packet.sender().isBlank()
                || packet.receiver() == null || packet.receiver().isBlank()
                || packet.messageId() == null || packet.messageId().length != MESSAGE_ID_BYTES
                || packet.nonce() == null || packet.nonce().length != NONCE_BYTES) {
            throw new CryptoException("Packet identity, message ID, or nonce is invalid");
        }
        if (packet.type() == PacketType.SESSION_MESSAGE) {
            validateSessionMetadata(packet.sessionId(), packet.sequence());
        }
        byte allowedFlags = (byte) (FLAG_SIGNED | FLAG_COMPRESSED | FLAG_SESSION_RESPONSE);
        if ((packet.flags() & ~allowedFlags) != 0) {
            throw new CryptoException("Packet contains unsupported flags");
        }
        boolean signedFlag = (packet.flags() & FLAG_SIGNED) != 0;
        if (signedFlag != packet.signed()) {
            throw new CryptoException("Packet signed flag and signature field disagree");
        }
        if ((packet.type() == PacketType.SIGNED_KEM_MESSAGE || packet.type() == PacketType.SESSION_EXCHANGE)
                && !signedFlag) {
            throw new CryptoException("Packet type requires a signature: " + packet.type());
        }
        if (packet.type() == PacketType.KEM_MESSAGE && signedFlag) {
            throw new CryptoException("Unsigned KEM packet type contains a signature");
        }
        if ((packet.flags() & FLAG_SESSION_RESPONSE) != 0 && packet.type() != PacketType.SESSION_EXCHANGE) {
            throw new CryptoException("Session response flag is set on a non-exchange packet");
        }

    }

    /**
     * Requires a correctly encoded 16-byte session identifier and a usable nonnegative sequence below
     * counter exhaustion. This establishes structural validity, not whether the session epoch or sequence
     * is currently authorized.
     *
     * @param sessionId the identifier of the expected session epoch
     * @param sequence the record or control sequence in the relevant replay domain
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static void validateSessionMetadata(String sessionId, long sequence) throws CryptoException {
        try {
            if (sessionId == null || Base64Url.decode(sessionId).length != 16 || sequence < 0
                    || sequence == Long.MAX_VALUE) {
                throw new CryptoException("Invalid session ID or sequence");
            }
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid session ID", e);
        }
    }

    /**
     * Performs the kem algorithm operation for the packet cryptography service.
     *
     * @param record the record supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static KemAlgorithm kemAlgorithm(KeyRecord record) throws CryptoException {
        if (record == null) {
            throw new CryptoException("KEM key record is missing");
        }
        return kemAlgorithm(record.algorithm());
    }

    /**
     * Performs the kem algorithm operation for the packet cryptography service.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static KemAlgorithm kemAlgorithm(String value) throws CryptoException {
        try {
            return KemAlgorithm.fromIdentifier(value);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * Performs the signature algorithm operation for the packet cryptography service.
     *
     * @param record the record supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static SignatureAlgorithm signatureAlgorithm(KeyRecord record) throws CryptoException {
        if (record == null) {
            throw new CryptoException("Signature key record is missing");
        }
        return signatureAlgorithm(record.algorithm());
    }

    /**
     * Performs the signature algorithm operation for the packet cryptography service.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static SignatureAlgorithm signatureAlgorithm(String value) throws CryptoException {
        try {
            return SignatureAlgorithm.fromIdentifier(value);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * Performs the aead algorithm operation for the packet cryptography service.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static AeadAlgorithm aeadAlgorithm(String value) throws CryptoException {
        try {
            return AeadAlgorithm.fromIdentifier(value);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    /**
     * Checks the hkdf required by the packet cryptography service and rejects invalid state instead of
     * continuing.
     *
     * @param value the value supplied to this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static void validateHkdf(String value) throws CryptoException {
        if (!AlgorithmSuite.HKDF_SHA256.equalsIgnoreCase(value)) {
            throw new CryptoException("Unsupported HKDF algorithm: " + value);
        }
    }

    /**
     * Checks the same algorithm required by the packet cryptography service and rejects invalid state
     * instead of continuing.
     *
     * @param type the type supplied to this operation
     * @param packetAlgorithm the packet algorithm supplied to this operation
     * @param keyAlgorithm the key algorithm supplied to this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static void requireSameAlgorithm(String type, String packetAlgorithm, String keyAlgorithm)
            throws CryptoException {
        if (!packetAlgorithm.equalsIgnoreCase(keyAlgorithm)) {
            throw new CryptoException("Packet " + type + " algorithm " + packetAlgorithm
                    + " does not match key algorithm " + keyAlgorithm);
        }
    }

    /**
     * Decodes Base64URL private material through KemCrypto with the exact selected suite and overwrites
     * the temporary decoded encoding in finally. Provider-owned key objects and immutable source strings
     * may retain copies.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param base64 the base64 supplied to this operation
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static PrivateKey decodeKemPrivateKey(KemAlgorithm algorithm, String base64)
            throws GeneralSecurityException, CryptoException {
        byte[] encoded = Base64Url.decode(base64);
        try {
            return KemCrypto.decodePrivate(algorithm, encoded);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Decodes Base64URL private material through SignatureCrypto using the exact suite and overwrites the
     * temporary decoded encoding in finally. This is best-effort buffer cleanup, not guaranteed erasure of
     * provider or String storage.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param base64 the base64 supplied to this operation
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static PrivateKey decodeSignaturePrivateKey(SignatureAlgorithm algorithm, String base64)
            throws GeneralSecurityException, CryptoException {
        byte[] encoded = Base64Url.decode(base64);
        try {
            return SignatureCrypto.decodePrivate(algorithm, encoded);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Initializes the selected AEAD with its required key and nonce parameters, supplies canonical
     * metadata as AAD, and returns ciphertext with its authentication tag. The same nonce must not be
     * reused with the same key.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param key the cryptographic key material for this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @param aad the additional authenticated data bound to the ciphertext
     * @param plaintext the plaintext bytes to encrypt or process
     * @return the resulting array produced by this operation
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    private static byte[] aeadEncrypt(AeadAlgorithm algorithm, byte[] key, byte[] nonce, byte[] aad,
                                      byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = aeadCipher(algorithm);
        initAeadCipher(cipher, Cipher.ENCRYPT_MODE, algorithm, key, nonce);
        /*
         * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
         * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
         * tag.
         */
        cipher.updateAAD(aad);
        /*
         * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
         * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
         * output when finalization fails.
         */
        return cipher.doFinal(plaintext);
    }

    /**
     * Initializes the selected AEAD and authenticates the supplied canonical metadata and ciphertext. JCA
     * doFinal verifies the authentication tag before this method returns plaintext; authentication
     * failures propagate without an unauthenticated fallback.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @param key the cryptographic key material for this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @param aad the additional authenticated data bound to the ciphertext
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @return the resulting array produced by this operation
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    private static byte[] aeadDecrypt(AeadAlgorithm algorithm, byte[] key, byte[] nonce, byte[] aad,
                                      byte[] ciphertext) throws GeneralSecurityException {
        Cipher cipher = aeadCipher(algorithm);
        initAeadCipher(cipher, Cipher.DECRYPT_MODE, algorithm, key, nonce);
        /*
         * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
         * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
         * tag.
         */
        cipher.updateAAD(aad);
        /*
         * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
         * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
         * output when finalization fails.
         */
        return cipher.doFinal(ciphertext);
    }

    /**
     * Obtains the explicit AES/GCM/NoPadding or ChaCha20-Poly1305 transformation from JCA. There is no
     * ECB, unauthenticated mode or silent algorithm downgrade; the installed providers supply the actual
     * primitive implementation.
     *
     * @param algorithm the selected algorithm and parameter-set definition
     * @return the result described above
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    private static Cipher aeadCipher(AeadAlgorithm algorithm) throws GeneralSecurityException {
        return switch (algorithm) {
            /*
             * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
             * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
             * provider or tag failure.
             */
            case AES_256_GCM -> Cipher.getInstance("AES/GCM/NoPadding");
            /*
             * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
             * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
             * provider or tag failure.
             */
            case CHACHA20_POLY1305 -> Cipher.getInstance("ChaCha20-Poly1305");
        };
    }

    /**
     * Configures AES-GCM with a 128-bit tag and the supplied nonce, or ChaCha20-Poly1305 with its nonce
     * and named key. JCA validates the parameter combination. Callers must provide the appropriate nonce
     * length and avoid reuse under a key.
     *
     * @param cipher the cipher supplied to this operation
     * @param mode the mode supplied to this operation
     * @param algorithm the selected algorithm and parameter-set definition
     * @param key the cryptographic key material for this operation
     * @param nonce the nonce associated with this cryptographic operation
     * @throws GeneralSecurityException if the selected cryptographic provider cannot perform the operation
     */
    private static void initAeadCipher(Cipher cipher, int mode, AeadAlgorithm algorithm, byte[] key, byte[] nonce)
            throws GeneralSecurityException {
        switch (algorithm) {
            /*
             * Supplies the explicit AES-GCM tag length and nonce to JCA. Nonce uniqueness under a key is a caller
             * responsibility; constructing a parameter object neither generates a nonce nor validates peer
             * identity.
             */
            case AES_256_GCM -> cipher.init(mode, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            case CHACHA20_POLY1305 -> cipher.init(mode, new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(nonce));
        }
    }

    /**
     * Extracts KEM secret bytes and derives a separate 32-byte AEAD key with HKDF-SHA256, using message ID
     * salt and the message-AEAD domain label. The secret copy is overwritten in finally rather than used
     * directly as an encryption key.
     *
     * @param secret the shared secret used as key-derivation input
     * @param messageId the message identifier used for correlation or key-derivation context
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static byte[] deriveMessageKey(SecretKeyWithEncapsulation secret, byte[] messageId)
            throws CryptoException {
        byte[] encoded = secret.getEncoded();
        try {
            return hkdf(encoded, messageId,
                    "krypt04mcg message aead".getBytes(StandardCharsets.UTF_8), AEAD_KEY_BYTES);
        } finally {
            /*
             * Overwrites this mutable buffer on the shown lifecycle path. Cleanup is best effort in the JVM:
             * immutable Strings, returned copies and provider/native key objects may retain other copies.
             */
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Delegates RFC 5869 extract-and-expand to Bouncy Castle using HMAC-SHA256. Input key material
     * supplies entropy, salt identifies the extraction context, and info provides protocol/purpose
     * separation. Output length is explicit; HKDF does not add entropy to a weak secret or authenticate
     * metadata by itself.
     *
     * @param ikm the input key material supplied to HKDF
     * @param salt the HKDF extraction salt
     * @param info the HKDF domain/context information
     * @param length the requested or declared byte count
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) throws CryptoException {
        try {
            /*
             * Delegates RFC 5869 extract-and-expand to Bouncy Castle with SHA-256. Input secret entropy, salt and
             * purpose-specific info have distinct roles; HKDF does not authenticate those context fields by
             * itself.
             */
            var hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(ikm, salt, info));
            byte[] key = new byte[length];
            hkdf.generateBytes(key, 0, key.length);
            return key;
        } catch (IllegalArgumentException e) {
            throw new CryptoException("HKDF failed", e);
        }
    }

    /**
     * Compresses already-bounded plaintext with the JDK DEFLATE implementation and releases native
     * compressor resources. Compression precedes encryption and can reveal length-dependent information;
     * it is not a security transformation.
     *
     * @param plaintext the plaintext bytes to encrypt or process
     * @return the resulting array produced by this operation
     */
    private static byte[] deflate(byte[] plaintext) {
        /*
         * Uses JDK DEFLATE after plaintext size admission and releases compressor resources in the surrounding
         * lifecycle. Compression changes visible ciphertext length and is not an authentication or
         * confidentiality primitive.
         */
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try {
            deflater.setInput(plaintext);
            deflater.finish();
            byte[] buffer = new byte[512];
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    /**
     * Inflates authenticated compressed data under the configured plaintext ceiling and rejects malformed,
     * truncated or excessive output. The limit prevents unlimited decompression allocation; it does not
     * guarantee negligible CPU cost for every compressed input.
     *
     * @param compressed the compressed supplied to this operation
     * @return the resulting array produced by this operation
     * @throws CryptoException if cryptographic input validation, parameter matching or authentication fails
     */
    private byte[] inflate(byte[] compressed) throws CryptoException {
        /*
         * Uses JDK inflation only for authenticated payloads in the decrypt path, with a bounded output loop.
         * Truncation, malformed streams and expansion beyond the configured plaintext limit must fail;
         * bounding output does not imply constant CPU cost.
         */
        Inflater inflater = new Inflater(true);
        inflater.setInput(compressed);
        byte[] buffer = new byte[512];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count > 0) {
                    if (out.size() + count > maxPlaintextBytes) {
                        throw new CryptoException("Compressed message expands beyond limit");
                    }
                    out.write(buffer, 0, count);
                } else if (!inflater.finished()) {
                    throw new CryptoException("Compressed message is truncated or invalid");
                }
            }
            if (inflater.getRemaining() != 0) {
                throw new CryptoException("Compressed message contains trailing bytes");
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new CryptoException("Compressed message is invalid", e);
        } finally {
            inflater.end();
        }
    }
}
