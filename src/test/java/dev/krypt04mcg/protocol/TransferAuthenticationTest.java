package dev.krypt04mcg.protocol;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.PublicIdentity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class TransferAuthenticationTest {
    @Test
    void directDecryptRejectsForgedUnsignedTransferEnvelopes() throws Exception {
        var crypto = new CryptoService();
        var bob = crypto.generateLocalKeys("Bob", "bob", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.ML_DSA_44);
        var receiver = new PublicIdentity("Bob", "bob", bob.kemPublicKey(), bob.signaturePublicKey());
        // Anyone with Bob's public key can encrypt while claiming another sender name.
        var file = crypto.encryptFor(receiver, null, "Alice",
                "{\"domain\":\"krypt04mcg:file:v1\",\"name\":\"forged.txt\",\"data\":\"YQ\"}", false);
        var data = crypto.encryptFor(receiver, null, "Alice",
                "{\"domain\":\"krypt04mcg:data:v1\",\"channel\":\"test\",\"data\":\"YQ\"}", false);
        assertThrows(IllegalArgumentException.class, () -> new FileTransferCodec().decrypt(file, bob, null));
        assertThrows(IllegalArgumentException.class, () -> new DataTransferCodec().decrypt(data, bob, null));
    }
}
