package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

final class KeyParameterBindingTest {
    @Test
    void rejectsRelabeledKemPublicAndPrivateKeys() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial keys = crypto.generateLocalKeys("alice", "alice-uuid",
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);
        KeyRecord publicKey = relabel(keys.kemPublicKey(), "ML-KEM-1024/public");
        KeyRecord privateKey = relabel(keys.kemPrivateKey(), "ML-KEM-1024/private");
        assertThrows(CryptoException.class, () -> crypto.validatePublicIdentity(new PublicIdentity(
                "alice", "alice-uuid", publicKey, keys.signaturePublicKey())));
        assertThrows(CryptoException.class, () -> crypto.validateEphemeralKemPublicKey(
                "ML-KEM-1024", "alice", "alice-uuid", publicKey.keyData(), publicKey.createdAt()));
        assertThrows(CryptoException.class, () -> crypto.validateLocalKeyMaterial(new LocalKeyMaterial(
                publicKey, privateKey, keys.signaturePublicKey(), keys.signaturePrivateKey()), "alice", "alice-uuid"));
        assertThrows(CryptoException.class, () -> crypto.validateLocalKeyMaterial(new LocalKeyMaterial(
                keys.kemPublicKey(), privateKey, keys.signaturePublicKey(), keys.signaturePrivateKey()), "alice", "alice-uuid"));
    }

    @Test
    void rejectsRelabeledSignatureKeys() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial keys = crypto.generateLocalKeys("alice", "alice-uuid",
                KemAlgorithm.ML_KEM_512, SignatureAlgorithm.ML_DSA_44);
        KeyRecord publicKey = relabel(keys.signaturePublicKey(), "ML-DSA-87/public");
        KeyRecord privateKey = relabel(keys.signaturePrivateKey(), "ML-DSA-87/private");
        assertThrows(CryptoException.class, () -> crypto.validatePublicIdentity(new PublicIdentity(
                "alice", "alice-uuid", keys.kemPublicKey(), publicKey)));
        assertThrows(CryptoException.class, () -> crypto.validateLocalKeyMaterial(new LocalKeyMaterial(
                keys.kemPublicKey(), keys.kemPrivateKey(), publicKey, privateKey), "alice", "alice-uuid"));
    }

    private static KeyRecord relabel(KeyRecord record, String algorithm) {
        return new KeyRecord(algorithm, record.owner(), record.uuid(), record.fingerprint(),
                record.createdAt(), record.keyData());
    }
}
