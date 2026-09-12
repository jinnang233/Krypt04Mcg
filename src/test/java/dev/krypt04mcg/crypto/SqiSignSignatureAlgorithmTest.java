package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.util.JsonSupport;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SqiSignSignatureAlgorithmTest {
    private static final byte[] MESSAGE = "SQIsign signature test".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path tempDir;

    @Test
    void exposesEveryBouncyCastleSqiSignParameterSet() throws Exception {
        var supported = Arrays.stream(SignatureAlgorithm.values())
                .filter(algorithm -> algorithm.parameterSpec() instanceof SQIsignParameterSpec)
                .map(algorithm -> algorithm.parameterSpec())
                .collect(Collectors.toSet());
        for (var field : SQIsignParameterSpec.class.getFields()) {
            if (field.getType() == SQIsignParameterSpec.class) {
                assertTrue(supported.remove(field.get(null)), field.getName());
            }
        }
        assertTrue(supported.isEmpty());
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = "SQISIGN_.*", mode = EnumSource.Mode.MATCH_ALL)
    void persistsSignsVerifiesAndTransportsEveryParameterSet(SignatureAlgorithm algorithm) throws Exception {
        var gson = JsonSupport.prettyGson();
        Krypt04McgConfig config = gson.fromJson(
                "{\"signatureAlgorithm\":\"" + algorithm.identifier() + "\"}", Krypt04McgConfig.class);
        assertEquals(algorithm, config.signatureAlgorithm);
        assertEquals(algorithm, gson.fromJson(gson.toJson(config), Krypt04McgConfig.class).signatureAlgorithm);
        assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(
                " " + algorithm.identifier().toLowerCase(Locale.ROOT) + "/PUBLIC "));

        CryptoService crypto = new CryptoService();
        Path storePath = tempDir.resolve(algorithm.name());
        KeyStoreService original = new KeyStoreService(storePath, crypto);
        original.init("alice", "alice-uuid", KemAlgorithm.ML_KEM_512, algorithm);
        KeyStoreService reloaded = new KeyStoreService(storePath, crypto);
        reloaded.init("alice", "alice-uuid", KemAlgorithm.ML_KEM_768, SignatureAlgorithm.FALCON_512);
        assertEquals(original.local(), reloaded.local());
        assertEquals(algorithm.identifier() + "/private", reloaded.local().signaturePrivateKey().algorithm());
        assertEquals(algorithm.identifier() + "/public", reloaded.local().signaturePublicKey().algorithm());
        var publicIdentity = crypto.validatePublicIdentity(reloaded.ownPublicIdentity());

        byte[] signature = crypto.sign(reloaded.local().signaturePrivateKey(), MESSAGE);
        assertTrue(crypto.verify(publicIdentity.signaturePublicKey(), MESSAGE, signature));
        assertFalse(crypto.verify(publicIdentity.signaturePublicKey(), new byte[]{1, 2, 3}, signature));

        SignatureAlgorithm other = algorithm == SignatureAlgorithm.SQISIGN_LVL1
                ? SignatureAlgorithm.SQISIGN_LVL3 : SignatureAlgorithm.SQISIGN_LVL1;
        KeyRecord key = publicIdentity.signaturePublicKey();
        KeyRecord mislabeled = new KeyRecord(other.identifier() + "/public", key.owner(), key.uuid(),
                key.fingerprint(), key.createdAt(), key.keyData());
        assertThrows(CryptoException.class, () -> crypto.verify(mislabeled, MESSAGE, signature));

        var bob = crypto.generateLocalKeys("bob", "bob-uuid", KemAlgorithm.ML_KEM_512,
                SignatureAlgorithm.FALCON_512);
        var bobPublic = new PublicIdentity("bob", "bob-uuid",
                bob.kemPublicKey(), bob.signaturePublicKey());
        EncryptedPacket packet = crypto.encryptFor(bobPublic, reloaded.local(), "alice", "SQIsign message", true);
        assertEquals(algorithm.identifier(), packet.algorithms().signature());
        PacketCodec codec = new PacketCodec();
        FragmentService fragments = new FragmentService();
        FragmentReassembler reassembler = new FragmentReassembler();
        Optional<byte[]> assembled = Optional.empty();
        for (String fragment : fragments.fragment(codec.encode(packet), packet.messageId(), 180)) {
            assembled = reassembler.accept(fragments.parse(fragment));
        }
        assertEquals("SQIsign message", crypto.decrypt(codec.decode(assembled.orElseThrow()), bob, publicIdentity));
    }
}
