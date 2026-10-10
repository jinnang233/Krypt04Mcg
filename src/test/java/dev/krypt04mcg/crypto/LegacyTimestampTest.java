package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.*;
import dev.krypt04mcg.model.*;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.util.Base64Url;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.junit.jupiter.api.Test;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class LegacyTimestampTest {
    /**
     * Verifies that unsigned legacy packets cannot bypass authenticated freshness.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test void unsignedLegacyPacketsCannotBypassAuthenticatedFreshness() throws Exception {
        var crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var identity = new PublicIdentity("Bob", "bob", keys.kemPublicKey(), keys.signaturePublicKey());
        var codec = new PacketCodec();
        for (byte version : new byte[]{1, 2}) {
            for (boolean signed : new boolean[]{false, true}) {
                /*
                 * Uses the selected JCA provider to decode the key encoding. Successful ASN.1 decoding alone is
                 * insufficient: the decoded parameter set and recorded public/private role are checked separately
                 * before cryptographic use.
                 *
                 * Wraps a SubjectPublicKeyInfo-style encoding for the selected provider. Encoded algorithm identifiers
                 * and decoded parameter sets must agree with the declared suite; parsing does not establish a trusted
                 * owner.
                 */
                var publicKey = KeyFactory.getInstance("ML-KEM", "BC").generatePublic(
                        new X509EncodedKeySpec(Base64Url.decode(keys.kemPublicKey().keyData())));
                /*
                 * Selects the BC KEM implementation for the declared suite. KEMGenerateSpec/KEMExtractSpec request no
                 * implicit provider KDF; the application applies its own purpose-separated HKDF to the recovered
                 * shared secret.
                 */
                var generator = KeyGenerator.getInstance("ML-KEM", "BC");
                /*
                 * Requests raw KEM shared-secret material with the provider KDF disabled. The AES name/bit length
                 * describes the adapter output, not an application encryption operation; message/hybrid code performs
                 * its own labeled HKDF before using a key.
                 */
                generator.init(new KEMGenerateSpec.Builder(publicKey, "AES", 256).withNoKdf().build());
                var secret = (SecretKeyWithEncapsulation) generator.generateKey();
                byte[] messageId = crypto.randomMessageId(), key = new byte[32];
                /*
                 * Delegates RFC 5869 extract-and-expand to Bouncy Castle with SHA-256. Input secret entropy, salt and
                 * purpose-specific info have distinct roles; HKDF does not authenticate those context fields by
                 * itself.
                 */
                var hkdf = new HKDFBytesGenerator(new SHA256Digest());
                hkdf.init(new HKDFParameters(secret.getEncoded(), messageId, "krypt04mcg message aead".getBytes(UTF_8)));
                hkdf.generateBytes(key, 0, key.length);
                var template = new EncryptedPacket(version, signed ? PacketType.SIGNED_KEM_MESSAGE : PacketType.KEM_MESSAGE,
                        (byte) (signed ? 1 : 0), "Bob", "Bob", 123L, messageId, (short) 0, (short) 1,
                        new AlgorithmSuite("ML-KEM-768", signed ? "ML-DSA-44" : "NONE", "AES-256-GCM", AlgorithmSuite.HKDF_SHA256),
                        new byte[12], secret.getEncapsulation(), new byte[0], new byte[0]);
                /*
                 * Requests the explicit authenticated-encryption transformation from JCA. Mode-specific key/nonce
                 * parameters and AAD are supplied before finalization; there is no unauthenticated-mode fallback on
                 * provider or tag failure.
                 */
                var cipher = Cipher.getInstance("AES/GCM/NoPadding");
                /*
                 * Supplies the explicit AES-GCM tag length and nonce to JCA. Nonce uniqueness under a key is a caller
                 * responsibility; constructing a parameter object neither generates a nonce nor validates peer
                 * identity.
                 */
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, template.nonce()));
                /*
                 * Authenticates these canonical metadata bytes without encrypting them. Both sides must reproduce
                 * identical AAD; changing an identity, epoch or other covered field invalidates the authentication
                 * tag.
                 */
                cipher.updateAAD(codec.aadFor(template));
                /*
                 * Finalizes the authenticated cipher operation. Decryption must not expose its result before tag
                 * verification succeeds; streaming adapters can already hold tentative plaintext and must erase that
                 * output when finalization fails.
                 */
                var encrypted = copy(template, template.timestampMillis(), cipher.doFinal("legacy".getBytes(UTF_8)), new byte[0]);
                var packet = copy(encrypted, encrypted.timestampMillis(), encrypted.ciphertext(),
                        signed ? crypto.sign(keys.signaturePrivateKey(), codec.signatureInput(encrypted)) : new byte[0]);
                var changed = copy(packet, System.currentTimeMillis(), packet.ciphertext(), packet.signature());
                assertArrayEquals(codec.aadFor(packet), codec.aadFor(changed), "Legacy AAD does not bind time");
                if (signed) assertEquals("legacy", crypto.decrypt(packet, keys, identity));
                else assertThrows(CryptoException.class, () -> crypto.decrypt(packet, keys, null));
                assertThrows(CryptoException.class, () -> crypto.decrypt(changed, keys, signed ? identity : null));
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    /**
     * Provides the copy fixture operation used by the legacy timestamp test regression scenarios.
     *
     * @param p the p supplied to this operation
     * @param time the time supplied to this operation
     * @param ciphertext the encoded ciphertext to authenticate or decode
     * @param signature the signature bytes or signature representation to verify
     * @return the result described above
     */
    private EncryptedPacket copy(EncryptedPacket p, long time, byte[] ciphertext, byte[] signature) {
        return new EncryptedPacket(p.protocolVersion(), p.type(), p.flags(), p.sender(), p.receiver(), time,
                p.messageId(), p.aadFragmentIndex(), p.aadFragmentTotal(), p.algorithms(), p.nonce(),
                p.kemCiphertext(), ciphertext, signature);
    }
}
