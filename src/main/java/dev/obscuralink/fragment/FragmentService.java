package dev.obscuralink.fragment;

import dev.obscuralink.model.Fragment;
import dev.obscuralink.util.Base64Url;
import dev.obscuralink.util.Hex;

import java.util.ArrayList;
import java.util.List;

public final class FragmentService {
    public static final String PREFIX = "[OBSCURA]";
    private static final int MIN_FRAGMENT_SIZE = 96;

    public List<String> fragment(byte[] packetBytes, byte[] messageId, int configuredPayloadSize) {
        int payloadSize = Math.max(MIN_FRAGMENT_SIZE, configuredPayloadSize);
        String encoded = Base64Url.encode(packetBytes);
        String id = Hex.encode(messageId);
        int total = Math.max(1, (int) Math.ceil(encoded.length() / (double) payloadSize));
        List<String> result = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            int start = i * payloadSize;
            int end = Math.min(encoded.length(), start + payloadSize);
            result.add(PREFIX + " " + id + " " + i + " " + total + " " + encoded.substring(start, end));
        }
        return result;
    }

    public boolean isFragment(String message) {
        return message != null && message.startsWith(PREFIX + " ");
    }

    public Fragment parse(String message) {
        if (!isFragment(message)) {
            throw new IllegalArgumentException("Not an ObscuraLink fragment");
        }
        String[] parts = message.split(" ", 5);
        if (parts.length != 5) {
            throw new IllegalArgumentException("Malformed ObscuraLink fragment");
        }
        int index = Integer.parseInt(parts[2]);
        int total = Integer.parseInt(parts[3]);
        if (index < 0 || total <= 0 || index >= total) {
            throw new IllegalArgumentException("Invalid fragment index " + index + "/" + total);
        }
        return new Fragment(parts[1], index, total, parts[4]);
    }
}
