package dev.krypt04mcg.fragment;

import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.model.FragmentProgress;
import dev.krypt04mcg.util.Base64Url;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;

public final class FragmentReassembler {
    public static final int DEFAULT_MAX_FRAGMENTS_PER_MESSAGE = ChatTransferLimits.MAX_FRAGMENTS;
    public static final int DEFAULT_MAX_MESSAGES_PER_SENDER = 16;

    private final Clock clock;
    private final Duration timeout;
    private final int maxMessages;
    private final int maxFragmentsPerMessage;
    private final Map<String, PartialMessage> partials = new HashMap<>();
    private Consumer<FragmentProgress> timeoutListener = ignored -> {};

    public FragmentReassembler() {
        this(Clock.systemUTC(), Duration.ofMinutes(2), 128, DEFAULT_MAX_FRAGMENTS_PER_MESSAGE);
    }

    public FragmentReassembler(Clock clock, Duration timeout, int maxMessages, int maxFragmentsPerMessage) {
        if (clock == null || timeout == null || timeout.isNegative() || timeout.isZero()
                || maxMessages <= 0 || maxFragmentsPerMessage <= 0) {
            throw new IllegalArgumentException("Invalid reassembly limits");
        }
        this.clock = clock;
        this.timeout = timeout;
        this.maxMessages = maxMessages;
        this.maxFragmentsPerMessage = maxFragmentsPerMessage;
    }

    public synchronized Optional<byte[]> accept(Fragment fragment) {
        return accept(fragment, null);
    }

    /** Sender must come from the transport, never from the unauthenticated packet body. */
    public synchronized Optional<byte[]> accept(Fragment fragment, String transportSender) {
        if (fragment == null || fragment.messageId() == null || fragment.messageId().isBlank()
                || fragment.total() <= 0 || fragment.index() < 0 || fragment.index() >= fragment.total()
                || fragment.payload() == null
                || fragment.payload().length() > FragmentService.MAX_CHAT_MESSAGE_LENGTH) {
            throw new IllegalArgumentException("Invalid fragment");
        }
        cleanupTimedOut();
        if (fragment.total() > maxFragmentsPerMessage) {
            throw new IllegalArgumentException("Too many fragments: " + fragment.total());
        }
        if (partials.size() >= maxMessages && !partials.containsKey(fragment.messageId())) {
            // Unauthenticated new IDs must not evict messages already being received.
            return Optional.empty();
        }
        String sender = transportSender == null ? null : transportSender.toLowerCase(Locale.ROOT);
        if (!partials.containsKey(fragment.messageId()) && sender != null
                && partials.values().stream().filter(partial -> sender.equals(partial.sender)).count()
                >= DEFAULT_MAX_MESSAGES_PER_SENDER) {
            return Optional.empty();
        }
        PartialMessage partial = partials.computeIfAbsent(fragment.messageId(),
                id -> new PartialMessage(fragment.total(), clock.millis(), sender));
        if (!Objects.equals(partial.sender, sender)) {
            throw new IllegalArgumentException("Fragment transport sender changed");
        }
        if (partial.total != fragment.total()) {
            throw new IllegalArgumentException("Fragment total changed for " + fragment.messageId());
        }
        if (!partial.fragments.containsKey(fragment.index())) {
            int added = fragment.payload().length();
            if (added > ChatTransferLimits.MAX_ENCODED_PACKET_CHARS - partial.chars) {
                remove(fragment.messageId());
                throw new IllegalArgumentException("Encrypted chat packet exceeds 256 KiB");
            }
            partial.fragments.put(fragment.index(), fragment.payload());
            partial.chars += added;
        }
        if (!partial.complete()) {
            return Optional.empty();
        }
        StringBuilder payload = new StringBuilder();
        for (int i = 0; i < partial.total; i++) {
            payload.append(partial.fragments.get(i));
        }
        remove(fragment.messageId());
        return Optional.of(Base64Url.decode(payload.toString()));
    }

    public synchronized int cleanup() {
        return cleanupTimedOut().size();
    }

    public synchronized List<FragmentProgress> cleanupTimedOut() {
        long cutoff = clock.millis() - timeout.toMillis();
        List<FragmentProgress> removed = partials.entrySet().stream()
                // The deadline is fixed at admission, including for fresh indices.
                .filter(entry -> entry.getValue().createdAt <= cutoff)
                .map(entry -> new FragmentProgress(entry.getKey(), entry.getValue().fragments.size(), entry.getValue().total))
                .toList();
        for (FragmentProgress progress : removed) {
            remove(progress.messageId());
            timeoutListener.accept(progress);
        }
        return removed;
    }

    public synchronized Optional<FragmentProgress> progress(String messageId) {
        PartialMessage partial = partials.get(messageId);
        if (partial == null) {
            return Optional.empty();
        }
        return Optional.of(new FragmentProgress(messageId, partial.fragments.size(), partial.total));
    }

    public synchronized int pendingMessages() {
        return partials.size();
    }

    public synchronized void clear() {
        partials.clear();
    }

    private void remove(String id) {
        partials.remove(id);
    }

    public synchronized void setTimeoutListener(Consumer<FragmentProgress> listener) {
        timeoutListener = Objects.requireNonNull(listener);
    }

    private static final class PartialMessage {
        private final int total;
        private final long createdAt;
        private final String sender;
        private final Map<Integer, String> fragments = new HashMap<>();
        private int chars;

        private PartialMessage(int total, long now, String sender) {
            this.total = total;
            this.createdAt = now;
            this.sender = sender;
        }

        private boolean complete() {
            return fragments.size() == total;
        }
    }
}
