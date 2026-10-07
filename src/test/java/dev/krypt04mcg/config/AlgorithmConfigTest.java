package dev.krypt04mcg.config;

import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.model.AlgorithmSuite;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class AlgorithmConfigTest {
    @ParameterizedTest
    @ValueSource(strings = {"CMCE/mceliece348864", "CMCE/mceliece348864f",
            "CMCE_MCELIECE348864", "CMCE_MCELIECE348864F"})
    void removedConfigSelectionsMigrateToMlKem768(String selection) {
        String json = """
                {
                  "kemAlgorithm": "%s",
                  "ephemeralKemAlgorithm": "%s",
                  "signatureAlgorithm": "Falcon-512",
                  "aeadAlgorithm": "AES-256-GCM"
                }
                """.formatted(selection, selection);

        Krypt04McgConfig config = JsonSupport.prettyGson().fromJson(json, Krypt04McgConfig.class);

        assertEquals(KemAlgorithm.ML_KEM_768, config.kemAlgorithm);
        assertEquals(KemAlgorithm.ML_KEM_768, config.ephemeralKemAlgorithm);
        assertEquals(SignatureAlgorithm.FALCON_512, config.signatureAlgorithm);
        assertEquals(AeadAlgorithm.AES_256_GCM, config.aeadAlgorithm);
    }

    @Test
    void newConfigsAndDefaultSuiteUseMlKem768() {
        Krypt04McgConfig config = JsonSupport.prettyGson().fromJson("{}", Krypt04McgConfig.class);
        assertEquals(KemAlgorithm.ML_KEM_768, config.kemAlgorithm);
        assertEquals(KemAlgorithm.ML_KEM_768, config.ephemeralKemAlgorithm);
        assertEquals("ML-KEM-768", AlgorithmSuite.defaults().kem());
    }

    @ParameterizedTest
    @ValueSource(strings = {"CMCE/mceliece348864", "CMCE/mceliece348864f"})
    void removedAlgorithmsAreRejectedInKeyAndPacketIdentifiers(String identifier) {
        assertThrows(IllegalArgumentException.class, () -> KemAlgorithm.fromIdentifier(identifier));
        assertThrows(IllegalArgumentException.class, () -> KemAlgorithm.fromIdentifier(identifier + "/public"));
        assertThrows(IllegalArgumentException.class, () -> KemAlgorithm.fromIdentifier(identifier + "/private"));
    }

    @Test
    void everyKeyIdentifierResolvesWithStoredKeyRoleSuffixes() {
        for (KemAlgorithm algorithm : KemAlgorithm.values()) {
            assertEquals(algorithm, KemAlgorithm.fromIdentifier(algorithm.identifier() + "/public"));
            assertEquals(algorithm, KemAlgorithm.fromIdentifier(algorithm.identifier() + "/private"));
        }
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "/public"));
            assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "/private"));
        }
    }
}
