package dev.krypt04mcg.config;

import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.model.AlgorithmSuite;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

final class AlgorithmConfigTest {
    @ParameterizedTest
    @ValueSource(strings = {"en_us", "zh_cn", "zh_tw", "de_de", "es_es", "fr_fr", "ja_jp", "ko_kr"})
    void everyAlgorithmHasLocalizedDropdownLabels(String locale) throws Exception {
        String resource = "/assets/krypt04mcg/lang/" + locale + ".json";
        try (var reader = new InputStreamReader(getClass().getResourceAsStream(resource), StandardCharsets.UTF_8)) {
            var labels = JsonSupport.prettyGson().fromJson(reader, JsonObject.class);
            String prefix = "text.autoconfig.krypt04mcg.option.";
            for (var algorithm : KemAlgorithm.values()) {
                for (String field : new String[] {"kemAlgorithm", "ephemeralKemAlgorithm"}) {
                    String key = prefix + field + "." + algorithm.name();
                    assertNotNull(labels.get(key), key);
                    String label = labels.get(key).getAsString();
                    assertFalse(label.isBlank());
                    if (algorithm.hybrid()) assertEquals(algorithm.identifier(), label);
                }
            }
            for (var algorithm : SignatureAlgorithm.values()) {
                String key = prefix + "signatureAlgorithm." + algorithm.name();
                assertNotNull(labels.get(key), key);
                String label = labels.get(key).getAsString();
                assertFalse(label.isBlank());
                if (algorithm.customHybrid()) assertEquals(algorithm.identifier(), label);
            }
        }
    }

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
    void newConfigsAndDefaultSuiteUseHybridAlgorithms() {
        Krypt04McgConfig config = JsonSupport.prettyGson().fromJson("{}", Krypt04McgConfig.class);
        assertEquals(KemAlgorithm.ML_KEM_768_X25519, config.kemAlgorithm);
        assertEquals(KemAlgorithm.ML_KEM_768_X25519, config.ephemeralKemAlgorithm);
        assertEquals(SignatureAlgorithm.MLDSA65_ED25519_SHA512, config.signatureAlgorithm);
        assertEquals("MLDSA65-Ed25519-SHA512", AlgorithmSuite.defaults().signature());
        assertEquals("ML-KEM-768+X25519", AlgorithmSuite.defaults().kem());
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
