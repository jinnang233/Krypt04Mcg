package dev.krypt04mcg.config;

import me.shedaniel.autoconfig.AutoConfig;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ClothConfigModIdTest {
    @Test
    void optionalIntegrationDetectsTheModIdPublishedByClothConfig() throws Exception {
        Path artifact = Path.of(AutoConfig.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        try (JarFile jar = new JarFile(artifact.toFile())) {
            var metadata = jar.getJarEntry("META-INF/neoforge.mods.toml");
            assertNotNull(metadata, "The dependency must be the NeoForge Cloth Config artifact");
            String toml;
            try (var input = jar.getInputStream(metadata)) {
                toml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
            var modId = Pattern.compile("(?m)^modId\\s*=\\s*\"([^\"]+)\"").matcher(toml);
            assertTrue(modId.find(), "Cloth Config must declare a mod ID");
            assertEquals(modId.group(1), OptionalClothConfig.CLOTH_CONFIG_MOD_ID,
                    "Config loading, saving and screens must detect the published NeoForge mod ID");
        }
    }
}
