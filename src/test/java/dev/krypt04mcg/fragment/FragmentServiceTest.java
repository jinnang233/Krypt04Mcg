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

    @Test
    void supportsCustomPrefix() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[]{1, 2, 3};

        List<String> lines = service.fragment(packet, fixedId(), 96, "[CUSTOM]");

        assertTrue(lines.getFirst().startsWith("[CUSTOM] "));
        assertTrue(service.isFragment(lines.getFirst(), "[CUSTOM]"));
        assertEquals(0, service.parse(lines.getFirst(), "[CUSTOM]").index());
    }

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

    @Test
    void rejectsMessagesBeyondReceiverFragmentLimit() {
        FragmentService service = new FragmentService();
        byte[] packet = new byte[12_288];
        List<String> lines = service.fragment(packet, fixedId(), 32);
        assertEquals(FragmentReassembler.DEFAULT_MAX_FRAGMENTS_PER_MESSAGE, lines.size());
        FragmentReassembler reassembler = new FragmentReassembler();
        Optional<byte[]> result = Optional.empty();
        for (String line : lines) {
            result = reassembler.accept(service.parse(line));
        }
        assertArrayEquals(packet, result.orElseThrow());
        assertThrows(IllegalArgumentException.class,
                () -> service.fragment(new byte[packet.length + 1], fixedId(), 32));
    }

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

    @Test
    void findsEmptyPrefixFragmentInsideDecoratedChatLine() {
        FragmentService service = new FragmentService();
        String fragment = "00000000000000000000000000000000 0 1 AQID";

        assertEquals(fragment, service.findFragment("<alice> " + fragment, ""));
    }

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

    private static byte[] fixedId() {
        return new byte[16];
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.EPOCH;

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
