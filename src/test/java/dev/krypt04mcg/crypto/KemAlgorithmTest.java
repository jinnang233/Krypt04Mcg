package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class KemAlgorithmTest {
    @ParameterizedTest
    @EnumSource(KemAlgorithm.class)
    void serializesValidatesAndEncrypts(KemAlgorithm algorithm) throws Exception {
        var gson = JsonSupport.prettyGson();
        assertEquals(algorithm, gson.fromJson(gson.toJson(algorithm), KemAlgorithm.class));
        CryptoService crypto = new CryptoService();
        var keys = crypto.generateLocalKeys("alice", "alice-uuid", algorithm, SignatureAlgorithm.ML_DSA_44);
        crypto.validateLocalKeyMaterial(keys, "alice", "alice-uuid");
        var identity = new PublicIdentity("alice", "alice-uuid", keys.kemPublicKey(), keys.signaturePublicKey());
        crypto.validatePublicIdentity(identity);
        crypto.validateEphemeralKemPublicKey(algorithm.identifier(), "alice", "alice-uuid",
                keys.kemPublicKey().keyData(), keys.kemPublicKey().createdAt());
        var packet = crypto.encryptFor(identity, keys, "alice", "kem round trip", true);
        assertEquals("kem round trip", crypto.decrypt(packet, keys, identity));
    }
}
