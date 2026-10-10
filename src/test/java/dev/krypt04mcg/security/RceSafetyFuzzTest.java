package dev.krypt04mcg.security;

import dev.krypt04mcg.fragment.FragmentService;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RceSafetyFuzzTest {
    private static final SecureRandom SEED_RANDOM = new SecureRandom();
    private static final int CASES = 500;

    /**
     * Verifies that randomized command like payloads never produce command chat lines.
     */
    @Test
    void randomizedCommandLikePayloadsNeverProduceCommandChatLines() {
        FragmentService fragmentService = new FragmentService();
        Random random = random("randomizedCommandLikePayloadsNeverProduceCommandChatLines");

        for (int i = 0; i < CASES; i++) {
            byte[] packet = randomCommandLikePayload(random).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            List<String> fragments = fragmentService.fragment(packet, randomBytes(random, 16), 1 + random.nextInt(512));

            for (String fragment : fragments) {
                assertFalse(fragment.startsWith("/"), "fragment could be interpreted as a command");
                assertTrue(fragment.startsWith(FragmentService.PREFIX + " "));
            }
        }
    }

    /**
     * Verifies that production sources do not use execution or dynamic loading apis.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void productionSourcesDoNotUseExecutionOrDynamicLoadingApis() throws Exception {
        List<String> forbidden = List.of(
                "Runtime.getRuntime",
                "ProcessBuilder",
                ".exec(",
                "ScriptEngine",
                "ObjectInputStream",
                ".readObject(",
                "Class.forName",
                "URLClassLoader",
                "System.load(",
                "System.loadLibrary("
        );

        for (Path source : productionJavaSources()) {
            String text = Files.readString(source);
            for (String token : forbidden) {
                assertFalse(text.contains(token), source + " contains potential RCE API " + token);
            }
        }
    }

    /**
     * Verifies that minecraft chat sender keeps fragment only guard.
     *
     * @throws Exception if the delegated operation cannot complete successfully
     */
    @Test
    void minecraftChatSenderKeepsFragmentOnlyGuard() throws Exception {
        String modSource = Files.readString(Path.of("src/client/java/dev/krypt04mcg/Krypt04McgMod.java"));

        assertTrue(modSource.contains("fragmentService.isFragment(line, config.packetPrefix)"));
        assertTrue(modSource.contains("sendChat(line)"));
        assertTrue(modSource.contains("sendCommand(formatServerCommand"));
    }

    /**
     * Provides the production java sources fixture operation used by the rce safety fuzz test regression
     * scenarios.
     *
     * @return the result described above
     * @throws Exception if the delegated operation cannot complete successfully
     */
    private static List<Path> productionJavaSources() throws Exception {
        try (var paths = Files.walk(Path.of("src"))) {
            return paths
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !path.toString().contains("\\test\\"))
                    .filter(path -> !path.toString().contains("/test/"))
                    .toList();
        }
    }

    /**
     * Provides the random command like payload fixture operation used by the rce safety fuzz test
     * regression scenarios.
     *
     * @param random the randomness source supplied to the cryptographic provider
     * @return the result described above
     */
    private static String randomCommandLikePayload(Random random) {
        String[] prefixes = {
                "/op ",
                "/execute ",
                "/tellraw ",
                "/function ",
                "/plugin:cmd ",
                "&& ",
                "| ",
                "$(",
                "`",
                "powershell -Command ",
                "cmd /c ",
                "bash -c "
        };
        StringBuilder builder = new StringBuilder(prefixes[random.nextInt(prefixes.length)]);
        int length = random.nextInt(256);
        for (int i = 0; i < length; i++) {
            builder.append((char) (32 + random.nextInt(95)));
        }
        return builder.toString();
    }

    /**
     * Provides the random fixture operation used by the rce safety fuzz test regression scenarios.
     *
     * @param testName the test name supplied to this operation
     * @return the result described above
     */
    private static Random random(String testName) {
        long seed = SEED_RANDOM.nextLong();
        System.out.println(RceSafetyFuzzTest.class.getSimpleName() + "." + testName + " seed=" + seed);
        return new Random(seed);
    }

    /**
     * Provides the random bytes fixture operation used by the rce safety fuzz test regression scenarios.
     *
     * @param random the randomness source supplied to the cryptographic provider
     * @param length the requested or declared byte count
     * @return the resulting array produced by this operation
     */
    private static byte[] randomBytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
