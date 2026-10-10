package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;

import java.util.Arrays;

public enum AeadAlgorithm {
    @SerializedName("AES-256-GCM")
    AES_256_GCM("AES-256-GCM"),
    @SerializedName("ChaCha20-Poly1305")
    CHACHA20_POLY1305("ChaCha20-Poly1305");

    private final String identifier;

    /**
     * Creates a aead algorithm with the supplied dependencies and initial state.
     *
     * @param identifier the identifier supplied to this operation
     */
    AeadAlgorithm(String identifier) {
        this.identifier = identifier;
    }

    /**
     * Returns the identifier value used by the aead algorithm.
     *
     * @return the result described above
     */
    public String identifier() {
        return identifier;
    }

    /**
     * Resolves the supplied values into the definition used by the aead algorithm.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     */
    public static AeadAlgorithm fromIdentifier(String value) {
        if (value == null) {
            throw new IllegalArgumentException("AEAD algorithm is missing");
        }
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.identifier.equalsIgnoreCase(value.trim()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported AEAD algorithm: " + value));
    }
}
