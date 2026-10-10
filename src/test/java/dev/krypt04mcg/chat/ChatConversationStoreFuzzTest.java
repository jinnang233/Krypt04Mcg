package dev.krypt04mcg.chat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ChatConversationStoreFuzzTest {
    private static final SecureRandom SEED_RANDOM = new SecureRandom();
    private static final int CASES = 150;

    @TempDir
    private Path tempDir;

    /**
     * Verifies that randomized conversation history remains bounded and reloadable.
     */
    @Test
    void randomizedConversationHistoryRemainsBoundedAndReloadable() {
        Random random = random("randomizedConversationHistoryRemainsBoundedAndReloadable");
        ChatConversationStore store = new ChatConversationStore(tempDir);
        List<String> playerTargets = new ArrayList<>();
        List<String> groupTargets = new ArrayList<>();

        for (int i = 0; i < CASES; i++) {
            String target = randomText(random, 1 + random.nextInt(40));
            String message = randomText(random, 1 + random.nextInt(220));
            if (random.nextBoolean()) {
                store.outgoing(target, message);
                playerTargets.add(target);
            } else {
                store.outgoingGroup(target, message);
                groupTargets.add(target);
            }
            if (random.nextBoolean()) {
                store.incoming(target, message);
                playerTargets.add(target);
            }
        }

        ChatConversationStore reloaded = assertDoesNotThrow(() -> new ChatConversationStore(tempDir));

        for (String target : playerTargets) {
            assertDoesNotThrow(() -> reloaded.messagesFor(target));
        }
        for (String target : groupTargets) {
            assertDoesNotThrow(() -> reloaded.messagesForGroup(target));
        }
        int totalMessages = playerTargets.stream().mapToInt(target -> reloaded.messagesFor(target).size()).sum()
                + groupTargets.stream().mapToInt(target -> reloaded.messagesForGroup(target).size()).sum();
        assertTrue(totalMessages <= 300 * Math.max(1, playerTargets.size() + groupTargets.size()));
    }

    /**
     * Verifies that blank targets and messages are ignored cleanly.
     */
    @Test
    void blankTargetsAndMessagesAreIgnoredCleanly() {
        Random random = random("blankTargetsAndMessagesAreIgnoredCleanly");
        ChatConversationStore store = new ChatConversationStore(tempDir);

        for (int i = 0; i < CASES; i++) {
            String blank = " ".repeat(random.nextInt(8));
            assertDoesNotThrow(() -> store.outgoing(blank, randomText(random, 12)));
            assertDoesNotThrow(() -> store.outgoingGroup(randomText(random, 12), blank));
            assertDoesNotThrow(() -> store.incoming(null, randomText(random, 12)));
            assertDoesNotThrow(() -> store.incoming(randomText(random, 12), null));
        }

        assertTrue(store.peers().isEmpty());
        assertTrue(store.groups().isEmpty());
    }

    /**
     * Provides the random fixture operation used by the chat conversation store fuzz test regression
     * scenarios.
     *
     * @param testName the test name supplied to this operation
     * @return the result described above
     */
    private static Random random(String testName) {
        long seed = SEED_RANDOM.nextLong();
        System.out.println(ChatConversationStoreFuzzTest.class.getSimpleName() + "." + testName + " seed=" + seed);
        return new Random(seed);
    }

    /**
     * Provides the random text fixture operation used by the chat conversation store fuzz test regression
     * scenarios.
     *
     * @param random the randomness source supplied to the cryptographic provider
     * @param maxLength the max length supplied to this operation
     * @return the result described above
     */
    private static String randomText(Random random, int maxLength) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.-#:/";
        int length = random.nextInt(maxLength + 1);
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        String value = builder.toString();
        return value.isBlank() ? "x" : value;
    }
}
