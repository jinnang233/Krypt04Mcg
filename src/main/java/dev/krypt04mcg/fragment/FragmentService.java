package dev.krypt04mcg.fragment;

import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FragmentService {
    public static final String PREFIX = "[KRYPT04MCG]";
    public static final int MAX_CHAT_MESSAGE_LENGTH = 256;
    private static final int MIN_PAYLOAD_SIZE = 32;
    private static final Pattern UNPREFIXED_FRAGMENT_PATTERN =
            Pattern.compile("(?<![0-9A-Fa-f])([0-9A-Fa-f]{32}\\s+\\d+\\s+\\d+\\s+[A-Za-z0-9_-]+)");

    /**
     * Performs the fragment operation for the chat wire fragmentation.
     *
     * @param packetBytes the packet bytes supplied to this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param configuredPayloadSize the configured payload size supplied to this operation
     * @return the result described above
     */
    public List<String> fragment(byte[] packetBytes, byte[] messageId, int configuredPayloadSize) {
        return fragment(packetBytes, messageId, configuredPayloadSize, PREFIX);
    }

    /**
     * Returns the recorded result for the chat wire fragmentation.
     *
     * @param packetBytes the packet bytes supplied to this operation
     * @param messageId the message identifier used for correlation or key-derivation context
     * @param configuredPayloadSize the configured payload size supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    public List<String> fragment(byte[] packetBytes, byte[] messageId, int configuredPayloadSize, String prefix) {
        if (packetBytes.length > ChatTransferLimits.MAX_PACKET_BYTES) {
            throw new IllegalArgumentException("Encrypted chat packet exceeds 256 KiB");
        }
        String encoded = Base64Url.encode(packetBytes);
        String id = Hex.encode(messageId);
        String normalizedPrefix = normalizePrefix(prefix);
        int payloadSize = payloadSizeFor(encoded.length(), id, configuredPayloadSize, normalizedPrefix);
        int total = Math.max(1, (int) Math.ceil(encoded.length() / (double) payloadSize));
        if (total > FragmentReassembler.DEFAULT_MAX_FRAGMENTS_PER_MESSAGE) {
            throw new IllegalArgumentException("Message requires too many fragments: " + total);
        }
        List<String> result = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            int start = i * payloadSize;
            int end = Math.min(encoded.length(), start + payloadSize);
            String line = headerPrefix(normalizedPrefix) + id + " " + i + " " + total + " " + encoded.substring(start, end);
            if (line.length() > MAX_CHAT_MESSAGE_LENGTH) {
                throw new IllegalStateException("Generated fragment exceeds Minecraft chat limit: " + line.length());
            }
            result.add(line);
        }
        return result;
    }

    /**
     * Reports whether fragment holds for the chat wire fragmentation.
     *
     * @param message the message supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean isFragment(String message) {
        return isFragment(message, PREFIX);
    }

    /**
     * Reports whether fragment holds for the chat wire fragmentation.
     *
     * @param message the message supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return whether the condition or operation described above succeeds
     */
    public boolean isFragment(String message, String prefix) {
        if (message == null || message.length() > MAX_CHAT_MESSAGE_LENGTH) {
            return false;
        }
        String normalizedPrefix = normalizePrefix(prefix);
        if (!normalizedPrefix.isEmpty() && !message.startsWith(normalizedPrefix + " ")) {
            return false;
        }
        FragmentParts parts = parts(message, normalizedPrefix);
        if (parts == null) {
            return false;
        }
        // Validate the wire grammar before an unauthenticated fragment reserves storage.
        if (!parts.messageId().matches("[0-9A-Fa-f]{32}")
                || !parts.index().matches("[0-9]{1,4}")
                || !parts.total().matches("[0-9]{1,4}")
                || !parts.payload().matches("[A-Za-z0-9_-]*")) {
            return false;
        }
        try {
            int index = Integer.parseInt(parts.index());
            int total = Integer.parseInt(parts.total());
            return total > 0 && total <= FragmentReassembler.DEFAULT_MAX_FRAGMENTS_PER_MESSAGE
                    && index < total;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Parses the supplied representation for the chat wire fragmentation.
     *
     * @param message the message supplied to this operation
     * @return the result described above
     */
    public Fragment parse(String message) {
        return parse(message, PREFIX);
    }

    /**
     * Parses the supplied representation for the chat wire fragmentation.
     *
     * @param message the message supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    public Fragment parse(String message, String prefix) {
        String normalizedPrefix = normalizePrefix(prefix);
        if (!isFragment(message, normalizedPrefix)) {
            throw new IllegalArgumentException("Not a Krypt04Mcg fragment");
        }
        if (message.length() > MAX_CHAT_MESSAGE_LENGTH) {
            throw new IllegalArgumentException("Krypt04Mcg fragment exceeds Minecraft chat limit");
        }
        FragmentParts parts = parts(message, normalizedPrefix);
        if (parts == null) {
            throw new IllegalArgumentException("Malformed Krypt04Mcg fragment");
        }
        int index = Integer.parseInt(parts.index());
        int total = Integer.parseInt(parts.total());
        if (index < 0 || total <= 0 || index >= total) {
            throw new IllegalArgumentException("Invalid fragment index " + index + "/" + total);
        }
        return new Fragment(parts.messageId(), index, total, parts.payload());
    }

    /**
     * Looks up fragment in the chat wire fragmentation without creating a replacement.
     *
     * @param message the message supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    public String findFragment(String message, String prefix) {
        if (message == null) {
            return null;
        }
        String normalizedPrefix = normalizePrefix(prefix);
        if (!normalizedPrefix.isEmpty()) {
            int index = message.indexOf(normalizedPrefix);
            return index < 0 ? null : message.substring(index);
        }
        Matcher matcher = UNPREFIXED_FRAGMENT_PATTERN.matcher(message);
        return matcher.find() ? matcher.group(1) : null;
    }

    /**
     * Returns the recorded adjusted for the chat wire fragmentation.
     *
     * @param encodedLength the encoded length supplied to this operation
     * @param id the id supplied to this operation
     * @param configuredPayloadSize the configured payload size supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    private static int payloadSizeFor(int encodedLength, String id, int configuredPayloadSize, String prefix) {
        int requested = Math.max(MIN_PAYLOAD_SIZE, configuredPayloadSize);
        // Small configured slices must not prevent otherwise valid large packets.
        requested = Math.max(requested, (encodedLength + ChatTransferLimits.MAX_FRAGMENTS - 1)
                / ChatTransferLimits.MAX_FRAGMENTS);
        int payloadSize = Math.min(requested, maxPayloadFor(id, 0, 1, prefix));
        while (true) {
            if (payloadSize < MIN_PAYLOAD_SIZE) {
                throw new IllegalArgumentException("Packet prefix leaves too little room for fragment payload");
            }
            int total = Math.max(1, (int) Math.ceil(encodedLength / (double) payloadSize));
            int maxPayload = maxPayloadFor(id, total - 1, total, prefix);
            int adjusted = Math.min(requested, maxPayload);
            if (adjusted == payloadSize) {
                return adjusted;
            }
            payloadSize = adjusted;
        }
    }

    /**
     * Performs the max payload for operation for the chat wire fragmentation.
     *
     * @param id the id supplied to this operation
     * @param index the index supplied to this operation
     * @param total the total supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    private static int maxPayloadFor(String id, int index, int total, String prefix) {
        int headerLength = headerPrefix(prefix).length()
                + id.length()
                + 1 + digits(index)
                + 1 + digits(total)
                + 1;
        return MAX_CHAT_MESSAGE_LENGTH - headerLength;
    }

    /**
     * Performs the parts operation for the chat wire fragmentation.
     *
     * @param message the message supplied to this operation
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    private static FragmentParts parts(String message, String prefix) {
        String body = prefix.isEmpty() ? message : message.substring(prefix.length() + 1);
        String[] parts = body.split("\\s+", 4);
        return parts.length == 4 ? new FragmentParts(parts[0], parts[1], parts[2], parts[3]) : null;
    }

    /**
     * Performs the header prefix operation for the chat wire fragmentation.
     *
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    private static String headerPrefix(String prefix) {
        return prefix.isEmpty() ? "" : prefix + " ";
    }

    /**
     * Normalizes prefix into the comparison/storage form used by the chat wire fragmentation.
     *
     * @param prefix the prefix supplied to this operation
     * @return the result described above
     */
    private static String normalizePrefix(String prefix) {
        return prefix == null ? PREFIX : prefix;
    }

    /**
     * Performs the digits operation for the chat wire fragmentation.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     */
    private static int digits(int value) {
        return Integer.toString(value).length();
    }

    private record FragmentParts(String messageId, String index, String total, String payload) {
    }
}
