package dev.krypt04mcg.fragment;

import dev.krypt04mcg.model.Fragment;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

final class FragmentServiceTest {
    /**
     * Verifies that maximum packet round trips with four digit indices and rejects one extra byte.
     */
    @Test void maximumPacketRoundTripsWithFourDigitIndicesAndRejectsOneExtraByte() {
        byte[] packet = new byte[ChatTransferLimits.MAX_PACKET_BYTES];
        new java.util.Random(42).nextBytes(packet);
        var service = new FragmentService();
        var assembler = new FragmentReassembler();
        var lines = service.fragment(packet, fixedId(), 180);
        assertTrue(lines.size() > 1024);
        Optional<byte[]> completed = Optional.empty();
        for (var line : lines) completed = assembler.accept(service.parse(line), "alice");
        assertArrayEquals(packet, completed.orElseThrow());
        assertThrows(IllegalArgumentException.class,
                () -> service.fragment(new byte[packet.length + 1], fixedId(), 180));
    }

    /**
     * Verifies that oversize encoded packet is removed without evicting other messages.
     */
    @Test void oversizeEncodedPacketIsRemovedWithoutEvictingOtherMessages() {
        var assembler = new FragmentReassembler();
        assembler.accept(new Fragment("victim", 0, 2, "AQ"), "bob");
        for (int i = 0; i < 1365; i++) assembler.accept(new Fragment("large", i, 2048, "A".repeat(256)), "alice");
        assertThrows(IllegalArgumentException.class,
                () -> assembler.accept(new Fragment("large", 1365, 2048, "A".repeat(256)), "alice"));
        assertTrue(assembler.progress("large").isEmpty());
        assertArrayEquals(new byte[]{1, 2, 3}, assembler.accept(new Fragment("victim", 1, 2, "ID"), "bob").orElseThrow());
    }
    /**
     * Verifies that sender flood cannot consume other senders assembly capacity.
     */
    @Test
    void senderFloodCannotConsumeOtherSendersAssemblyCapacity() {
        FragmentReassembler reassembler = new FragmentReassembler();
        for (int i = 0; i < 128; i++) {
            reassembler.accept(new Fragment("mallory:" + i, 0, 2, "AA"), i % 2 == 0 ? "Mallory" : "MALLORY");
        }
        assertEquals(FragmentReassembler.DEFAULT_MAX_MESSAGES_PER_SENDER, reassembler.pendingMessages());
        reassembler.accept(new Fragment("alice:message", 0, 2, "AQ"), "Alice");
        assertTrue(reassembler.progress("alice:message").isPresent());
        assertArrayEquals(new byte[]{1, 2, 3}, reassembler.accept(new Fragment("alice:message", 1, 2, "ID"), "ALICE").orElseThrow());
    }

    /**
     * Verifies that sender quota is released on completion expiry and disconnect clear.
     */
    @Test
    void senderQuotaIsReleasedOnCompletionExpiryAndDisconnectClear() {
        MutableClock clock = new MutableClock();
        FragmentReassembler reassembler = new FragmentReassembler(clock, Duration.ofSeconds(10), 128, 10);
        for (int i = 0; i < 16; i++) reassembler.accept(new Fragment("alice:" + i, 0, 2, "AQ"), "Alice");
        reassembler.accept(new Fragment("alice:overflow", 0, 2, "AQ"), "Alice");
        assertTrue(reassembler.progress("alice:overflow").isEmpty());
        assertArrayEquals(new byte[]{1, 2, 3}, reassembler.accept(new Fragment("alice:0", 1, 2, "ID"), "Alice").orElseThrow());
        reassembler.accept(new Fragment("alice:overflow", 0, 2, "AQ"), "Alice");
        assertTrue(reassembler.progress("alice:overflow").isPresent());
        clock.advance(Duration.ofSeconds(10));
        assertEquals(16, reassembler.cleanup());
        reassembler.accept(new Fragment("alice:new", 0, 2, "AQ"), "Alice");
        assertEquals(1, reassembler.pendingMessages());
        reassembler.clear();
        assertEquals(0, reassembler.pendingMessages());
        assertTrue(reassembler.accept(new Fragment("alice:new", 1, 2, "ID"), "Alice").isEmpty(),
                "Fragments from a retired connection must not complete on the new one");
    }

    /**
     * Verifies that sender cannot take over another sources assembly.
     */
    @Test
    void senderCannotTakeOverAnotherSourcesAssembly() {
        FragmentReassembler reassembler = new FragmentReassembler();
        reassembler.accept(new Fragment("id", 0, 2, "AQ"), "Alice");
        assertThrows(IllegalArgumentException.class,
                () -> reassembler.accept(new Fragment("id", 1, 2, "ID"), "Mallory"));
        assertEquals(1, reassembler.progress("id").orElseThrow().received());
        assertArrayEquals(new byte[]{1, 2, 3}, reassembler.accept(new Fragment("id", 1, 2, "ID"), "Alice").orElseThrow());
    }
    /**
     * Verifies that new fragments cannot keep an incomplete message alive past its deadline.
     */
    @Test
    void newFragmentsCannotKeepAnIncompleteMessageAlivePastItsDeadline() {
        MutableClock clock = new MutableClock();
        FragmentReassembler reassembler = new FragmentReassembler(clock, Duration.ofSeconds(10), 2, 10);
        reassembler.accept(new Fragment("alice:message", 0, 3, "AA"));
        clock.advance(Duration.ofSeconds(9));
        reassembler.accept(new Fragment("alice:message", 1, 3, "AA"));
        clock.advance(Duration.ofSeconds(1));
        assertEquals(1, reassembler.cleanup());
        assertEquals(0, reassembler.pendingMessages());
    }

    /**
     * Verifies that new message flood does not evict an admitted message.
     */
    @Test
    void newMessageFloodDoesNotEvictAnAdmittedMessage() {
        FragmentReassembler reassembler = new FragmentReassembler(
                Clock.systemUTC(), Duration.ofMinutes(1), 1, 10);
        reassembler.accept(new Fragment("alice:message", 0, 2, "AQ"));
        for (int i = 0; i < 100; i++) {
            assertTrue(reassembler.accept(new Fragment("mallory:" + i, 0, 2, "AA")).isEmpty());
        }
        assertEquals(1, reassembler.pendingMessages());
        assertArrayEquals(new byte[]{1, 2, 3},
                reassembler.accept(new Fragment("alice:message", 1, 2, "ID")).orElseThrow());
    }

    /**
     * Verifies that rejects malformed wire ids and payloads before reassembly.
     */
    @Test
    void rejectsMalformedWireIdsAndPayloadsBeforeReassembly() {
        FragmentService service = new FragmentService();
        String id = "00000000000000000000000000000000";
        for (String body : List.of("not-an-id 0 2 AA", id + " 0 2 AA!",
                id + " 0 2 AA BB", id + " +0 2 AA", id + " 0 2049 AA")) {
            String line = FragmentService.PREFIX + " " + body;
            assertTrue(!service.isFragment(line));
            assertThrows(IllegalArgumentException.class, () -> service.parse(line));
        }
    }

    /**
     * Verifies that duplicate fragments do not extend cache lifetime.
     */
    @Test
    void duplicateFragmentsDoNotExtendCacheLifetime() {
        MutableClock clock = new MutableClock();
        FragmentReassembler reassembler = new FragmentReassembler(clock, Duration.ofSeconds(10), 10, 10);
        Fragment fragment = new Fragment("abc", 0, 2, "AAA");
        reassembler.accept(fragment);
        clock.advance(Duration.ofSeconds(9));
        reassembler.accept(fragment);
        clock.advance(Duration.ofSeconds(2));
        assertEquals(1, reassembler.cleanup());
    }

    /**
     * Verifies that rejects invalid indices and oversized payloads before caching.
     */
    @Test
    void rejectsInvalidIndicesAndOversizedPayloadsBeforeCaching() {
        FragmentReassembler reassembler = new FragmentReassembler();
        for (Fragment fragment : List.of(new Fragment("abc", -1, 2, "AA"),
                new Fragment("abc", 2, 2, "AA"), new Fragment("abc", 0, 0, "AA"),
                new Fragment("abc", 0, 2, "A".repeat(257)))) {
            assertThrows(IllegalArgumentException.class, () -> reassembler.accept(fragment));
        }
        assertEquals(0, reassembler.pendingMessages());
    }

    /**
     * Verifies that reassembles out of order and ignores duplicate.
     */
    @Test
    void reassemblesOutOfOrderAndIgnoresDuplicate() {
        FragmentService service = new FragmentService();
        FragmentReassembler reassembler = new FragmentReassembler();
        byte[] packet = new byte[300];
        for (int i = 0; i < packet.length; i++) {
            packet[i] = (byte) i;
        }
        List<String> lines = service.fragment(packet, fixedId(), 96);

        Fragment second = service.parse(lines.get(1));
        Fragment first = service.parse(lines.get(0));
        assertTrue(reassembler.accept(second).isEmpty());
        assertTrue(reassembler.accept(second).isEmpty());
        Optional<byte[]> result = Optional.empty();
        for (int i = 0; i < lines.size(); i++) {
            result = reassembler.accept(service.parse(lines.get(i)));
        }

        assertTrue(result.isPresent());
        assertArrayEquals(packet, result.get());
    }

    /**
     * Verifies that caps fragments to minecraft chat limit.
     */
    @Test
    void capsFragmentsToMinecraftChatLimit() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[3000];
        for (int i = 0; i < packet.length; i++) {
            packet[i] = (byte) i;
        }

        List<String> lines = service.fragment(packet, fixedId(), 680);

        assertTrue(lines.size() > 1);
        for (String line : lines) {
            assertTrue(line.length() <= FragmentService.MAX_CHAT_MESSAGE_LENGTH,
                    "fragment length was " + line.length());
        }
    }

    /**
     * Verifies that supports custom prefix.
     */
    @Test
    void supportsCustomPrefix() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[]{1, 2, 3};

        List<String> lines = service.fragment(packet, fixedId(), 96, "[CUSTOM]");

        assertTrue(lines.getFirst().startsWith("[CUSTOM] "));
        assertTrue(service.isFragment(lines.getFirst(), "[CUSTOM]"));
        assertEquals(0, service.parse(lines.getFirst(), "[CUSTOM]").index());
    }

    /**
     * Verifies that rejects prefixes that cannot fit payload without hanging.
     */
    @Test
    void rejectsPrefixesThatCannotFitPayloadWithoutHanging() {
        FragmentService service = new FragmentService();

        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
            for (int length : new int[]{185, 218, 256}) {
                assertThrows(IllegalArgumentException.class,
                        () -> service.fragment(new byte[3000], fixedId(), 96, "P".repeat(length)));
            }
            // Initially fits the minimum payload, but the multi-digit fragment count needs more space.
            assertThrows(IllegalArgumentException.class,
                    () -> service.fragment(new byte[3000], fixedId(), 96, "P".repeat(184)));
        });
    }

    /**
     * Verifies that round trips prefix containing spaces.
     */
    @Test
    void roundTripsPrefixContainingSpaces() {
        FragmentService service = new FragmentService();
        FragmentReassembler reassembler = new FragmentReassembler();
        String prefix = "[CUSTOM CHAT]";
        byte[] packet = new byte[300];
        List<String> lines = service.fragment(packet, fixedId(), 96, prefix);
        Optional<byte[]> result = Optional.empty();

        for (String line : lines) {
            assertTrue(service.isFragment(line, prefix));
            result = reassembler.accept(service.parse(line, prefix));
        }
        assertArrayEquals(packet, result.orElseThrow());
    }

    /**
     * Verifies that increases small configured payload for maximum packet.
     */
    @Test
    void increasesSmallConfiguredPayloadForMaximumPacket() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[ChatTransferLimits.MAX_PACKET_BYTES];
        List<String> lines = service.fragment(packet, fixedId(), 32);
        assertTrue(lines.size() <= FragmentReassembler.DEFAULT_MAX_FRAGMENTS_PER_MESSAGE);
        assertTrue(service.parse(lines.getFirst()).payload().length() > 32);
        FragmentReassembler reassembler = new FragmentReassembler();
        Optional<byte[]> result = Optional.empty();
        for (String line : lines) {
            result = reassembler.accept(service.parse(line));
        }
        assertArrayEquals(packet, result.orElseThrow());
        assertThrows(IllegalArgumentException.class,
                () -> service.fragment(new byte[packet.length + 1], fixedId(), 32));
    }

    /**
     * Verifies that supports empty prefix.
     */
    @Test
    void supportsEmptyPrefix() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[]{1, 2, 3};

        List<String> lines = service.fragment(packet, fixedId(), 96, "");

        assertTrue(lines.getFirst().startsWith("00000000000000000000000000000000 0 1 "));
        assertTrue(service.isFragment(lines.getFirst(), ""));
        Fragment fragment = service.parse(lines.getFirst(), "");
        assertEquals("00000000000000000000000000000000", fragment.messageId());
        assertEquals(0, fragment.index());
        assertEquals(1, fragment.total());
    }

    /**
     * Verifies that finds empty prefix fragment inside decorated chat line.
     */
    @Test
    void findsEmptyPrefixFragmentInsideDecoratedChatLine() {
        FragmentService service = new FragmentService();
        String fragment = "00000000000000000000000000000000 0 1 AQID";

        assertEquals(fragment, service.findFragment("<alice> " + fragment, ""));
    }

    /**
     * Verifies that cleanup removes timed out messages.
     */
    @Test
    void cleanupRemovesTimedOutMessages() {
        MutableClock clock = new MutableClock();
        FragmentReassembler reassembler = new FragmentReassembler(clock, Duration.ofSeconds(1), 10, 10);
        Fragment fragment = new Fragment("abc", 0, 2, "aaa");
        assertTrue(reassembler.accept(fragment).isEmpty());
        assertEquals(1, reassembler.pendingMessages());
        clock.advance(Duration.ofSeconds(2));
        assertEquals(1, reassembler.cleanup());
        assertEquals(0, reassembler.pendingMessages());
    }

    /**
     * Provides the fixed id fixture operation used by the fragment service test regression scenarios.
     *
     * @return the resulting array produced by this operation
     */
    private static byte[] fixedId() {
        return new byte[16];
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.EPOCH;

        /**
         * Provides the advance fixture operation used by the fragment service test regression scenarios.
         *
         * @param duration the duration supplied to this operation
         */
        void advance(Duration duration) {
            now = now.plus(duration);
        }

        /**
         * Provides the get zone fixture operation used by the fragment service test regression scenarios.
         *
         * @return the result described above
         */
        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        /**
         * Provides the with zone fixture operation used by the fragment service test regression scenarios.
         *
         * @param zone the zone supplied to this operation
         * @return the result described above
         */
        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        /**
         * Provides the instant fixture operation used by the fragment service test regression scenarios.
         *
         * @return the result described above
         */
        @Override
        public Instant instant() {
            return now;
        }
    }
}
