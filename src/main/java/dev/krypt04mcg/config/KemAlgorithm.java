package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public enum KemAlgorithm {
    @SerializedName("CMCE/mceliece460896")
    CMCE_MCELIECE460896("CMCE/mceliece460896", "CMCE", "BC", CMCEParameterSpec.mceliece460896),
    @SerializedName("CMCE/mceliece460896f")
    CMCE_MCELIECE460896F("CMCE/mceliece460896f", "CMCE", "BC", CMCEParameterSpec.mceliece460896f),
    @SerializedName("CMCE/mceliece6688128")
    CMCE_MCELIECE6688128("CMCE/mceliece6688128", "CMCE", "BC", CMCEParameterSpec.mceliece6688128),
    @SerializedName("CMCE/mceliece6688128f")
    CMCE_MCELIECE6688128F("CMCE/mceliece6688128f", "CMCE", "BC", CMCEParameterSpec.mceliece6688128f),
    @SerializedName("CMCE/mceliece6960119")
    CMCE_MCELIECE6960119("CMCE/mceliece6960119", "CMCE", "BC", CMCEParameterSpec.mceliece6960119),
    @SerializedName("CMCE/mceliece6960119f")
    CMCE_MCELIECE6960119F("CMCE/mceliece6960119f", "CMCE", "BC", CMCEParameterSpec.mceliece6960119f),
    @SerializedName("CMCE/mceliece8192128")
    CMCE_MCELIECE8192128("CMCE/mceliece8192128", "CMCE", "BC", CMCEParameterSpec.mceliece8192128),
    @SerializedName("CMCE/mceliece8192128f")
    CMCE_MCELIECE8192128F("CMCE/mceliece8192128f", "CMCE", "BC", CMCEParameterSpec.mceliece8192128f),
    @SerializedName("HQC/hqc128")
    HQC_HQC128("HQC/hqc128", "HQC", "BCPQC", HQCParameterSpec.hqc128),
    @SerializedName("HQC/hqc192")
    HQC_HQC192("HQC/hqc192", "HQC", "BCPQC", HQCParameterSpec.hqc192),
    @SerializedName("HQC/hqc256")
    HQC_HQC256("HQC/hqc256", "HQC", "BCPQC", HQCParameterSpec.hqc256),
    @SerializedName("NTRULPRIME/ntrulpr653")
    NTRULPRIME_NTRULPR653("NTRULPRIME/ntrulpr653", "NTRULPRIME", "BCPQC", NTRULPRimeParameterSpec.ntrulpr653),
    @SerializedName("NTRULPRIME/ntrulpr761")
    NTRULPRIME_NTRULPR761("NTRULPRIME/ntrulpr761", "NTRULPRIME", "BCPQC", NTRULPRimeParameterSpec.ntrulpr761),
    @SerializedName("NTRULPRIME/ntrulpr857")
    NTRULPRIME_NTRULPR857("NTRULPRIME/ntrulpr857", "NTRULPRIME", "BCPQC", NTRULPRimeParameterSpec.ntrulpr857),
    @SerializedName("NTRULPRIME/ntrulpr953")
    NTRULPRIME_NTRULPR953("NTRULPRIME/ntrulpr953", "NTRULPRIME", "BCPQC", NTRULPRimeParameterSpec.ntrulpr953),
    @SerializedName("NTRULPRIME/ntrulpr1013")
    NTRULPRIME_NTRULPR1013("NTRULPRIME/ntrulpr1013", "NTRULPRIME", "BCPQC", NTRULPRimeParameterSpec.ntrulpr1013),
    @SerializedName("NTRULPRIME/ntrulpr1277")
    NTRULPRIME_NTRULPR1277("NTRULPRIME/ntrulpr1277", "NTRULPRIME", "BCPQC", NTRULPRimeParameterSpec.ntrulpr1277),
    @SerializedName("SNTRUPRIME/sntrup653")
    SNTRUPRIME_SNTRUP653("SNTRUPRIME/sntrup653", "SNTRUPRIME", "BCPQC", SNTRUPrimeParameterSpec.sntrup653),
    @SerializedName("SNTRUPRIME/sntrup761")
    SNTRUPRIME_SNTRUP761("SNTRUPRIME/sntrup761", "SNTRUPRIME", "BCPQC", SNTRUPrimeParameterSpec.sntrup761),
    @SerializedName("SNTRUPRIME/sntrup857")
    SNTRUPRIME_SNTRUP857("SNTRUPRIME/sntrup857", "SNTRUPRIME", "BCPQC", SNTRUPrimeParameterSpec.sntrup857),
    @SerializedName("SNTRUPRIME/sntrup953")
    SNTRUPRIME_SNTRUP953("SNTRUPRIME/sntrup953", "SNTRUPRIME", "BCPQC", SNTRUPrimeParameterSpec.sntrup953),
    @SerializedName("SNTRUPRIME/sntrup1013")
    SNTRUPRIME_SNTRUP1013("SNTRUPRIME/sntrup1013", "SNTRUPRIME", "BCPQC", SNTRUPrimeParameterSpec.sntrup1013),
    @SerializedName("SNTRUPRIME/sntrup1277")
    SNTRUPRIME_SNTRUP1277("SNTRUPRIME/sntrup1277", "SNTRUPRIME", "BCPQC", SNTRUPrimeParameterSpec.sntrup1277),
    @SerializedName("ML-KEM-512")
    ML_KEM_512("ML-KEM-512", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_512),
    // Migrate removed selections in saved configs; stored key identifiers remain strict.
    @SerializedName(value = "ML-KEM-768", alternate = {
            "CMCE/mceliece348864", "CMCE/mceliece348864f",
            "CMCE_MCELIECE348864", "CMCE_MCELIECE348864F"})
    ML_KEM_768("ML-KEM-768", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_768),
    @SerializedName("ML-KEM-1024")
    ML_KEM_1024("ML-KEM-1024", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_1024),
    @SerializedName("CMCE/mceliece460896+X25519")
    CMCE_MCELIECE460896_X25519("CMCE/mceliece460896+X25519", CMCE_MCELIECE460896, "X25519"),
    @SerializedName("CMCE/mceliece460896+X448")
    CMCE_MCELIECE460896_X448("CMCE/mceliece460896+X448", CMCE_MCELIECE460896, "X448"),
    @SerializedName("CMCE/mceliece460896f+X25519")
    CMCE_MCELIECE460896F_X25519("CMCE/mceliece460896f+X25519", CMCE_MCELIECE460896F, "X25519"),
    @SerializedName("CMCE/mceliece460896f+X448")
    CMCE_MCELIECE460896F_X448("CMCE/mceliece460896f+X448", CMCE_MCELIECE460896F, "X448"),
    @SerializedName("CMCE/mceliece6688128+X25519")
    CMCE_MCELIECE6688128_X25519("CMCE/mceliece6688128+X25519", CMCE_MCELIECE6688128, "X25519"),
    @SerializedName("CMCE/mceliece6688128+X448")
    CMCE_MCELIECE6688128_X448("CMCE/mceliece6688128+X448", CMCE_MCELIECE6688128, "X448"),
    @SerializedName("CMCE/mceliece6688128f+X25519")
    CMCE_MCELIECE6688128F_X25519("CMCE/mceliece6688128f+X25519", CMCE_MCELIECE6688128F, "X25519"),
    @SerializedName("CMCE/mceliece6688128f+X448")
    CMCE_MCELIECE6688128F_X448("CMCE/mceliece6688128f+X448", CMCE_MCELIECE6688128F, "X448"),
    @SerializedName("CMCE/mceliece6960119+X25519")
    CMCE_MCELIECE6960119_X25519("CMCE/mceliece6960119+X25519", CMCE_MCELIECE6960119, "X25519"),
    @SerializedName("CMCE/mceliece6960119+X448")
    CMCE_MCELIECE6960119_X448("CMCE/mceliece6960119+X448", CMCE_MCELIECE6960119, "X448"),
    @SerializedName("CMCE/mceliece6960119f+X25519")
    CMCE_MCELIECE6960119F_X25519("CMCE/mceliece6960119f+X25519", CMCE_MCELIECE6960119F, "X25519"),
    @SerializedName("CMCE/mceliece6960119f+X448")
    CMCE_MCELIECE6960119F_X448("CMCE/mceliece6960119f+X448", CMCE_MCELIECE6960119F, "X448"),
    @SerializedName("CMCE/mceliece8192128+X25519")
    CMCE_MCELIECE8192128_X25519("CMCE/mceliece8192128+X25519", CMCE_MCELIECE8192128, "X25519"),
    @SerializedName("CMCE/mceliece8192128+X448")
    CMCE_MCELIECE8192128_X448("CMCE/mceliece8192128+X448", CMCE_MCELIECE8192128, "X448"),
    @SerializedName("CMCE/mceliece8192128f+X25519")
    CMCE_MCELIECE8192128F_X25519("CMCE/mceliece8192128f+X25519", CMCE_MCELIECE8192128F, "X25519"),
    @SerializedName("CMCE/mceliece8192128f+X448")
    CMCE_MCELIECE8192128F_X448("CMCE/mceliece8192128f+X448", CMCE_MCELIECE8192128F, "X448"),
    @SerializedName("HQC/hqc128+X25519")
    HQC_HQC128_X25519("HQC/hqc128+X25519", HQC_HQC128, "X25519"),
    @SerializedName("HQC/hqc128+X448")
    HQC_HQC128_X448("HQC/hqc128+X448", HQC_HQC128, "X448"),
    @SerializedName("HQC/hqc192+X25519")
    HQC_HQC192_X25519("HQC/hqc192+X25519", HQC_HQC192, "X25519"),
    @SerializedName("HQC/hqc192+X448")
    HQC_HQC192_X448("HQC/hqc192+X448", HQC_HQC192, "X448"),
    @SerializedName("HQC/hqc256+X25519")
    HQC_HQC256_X25519("HQC/hqc256+X25519", HQC_HQC256, "X25519"),
    @SerializedName("HQC/hqc256+X448")
    HQC_HQC256_X448("HQC/hqc256+X448", HQC_HQC256, "X448"),
    @SerializedName("NTRULPRIME/ntrulpr653+X25519")
    NTRULPRIME_NTRULPR653_X25519("NTRULPRIME/ntrulpr653+X25519", NTRULPRIME_NTRULPR653, "X25519"),
    @SerializedName("NTRULPRIME/ntrulpr653+X448")
    NTRULPRIME_NTRULPR653_X448("NTRULPRIME/ntrulpr653+X448", NTRULPRIME_NTRULPR653, "X448"),
    @SerializedName("NTRULPRIME/ntrulpr761+X25519")
    NTRULPRIME_NTRULPR761_X25519("NTRULPRIME/ntrulpr761+X25519", NTRULPRIME_NTRULPR761, "X25519"),
    @SerializedName("NTRULPRIME/ntrulpr761+X448")
    NTRULPRIME_NTRULPR761_X448("NTRULPRIME/ntrulpr761+X448", NTRULPRIME_NTRULPR761, "X448"),
    @SerializedName("NTRULPRIME/ntrulpr857+X25519")
    NTRULPRIME_NTRULPR857_X25519("NTRULPRIME/ntrulpr857+X25519", NTRULPRIME_NTRULPR857, "X25519"),
    @SerializedName("NTRULPRIME/ntrulpr857+X448")
    NTRULPRIME_NTRULPR857_X448("NTRULPRIME/ntrulpr857+X448", NTRULPRIME_NTRULPR857, "X448"),
    @SerializedName("NTRULPRIME/ntrulpr953+X25519")
    NTRULPRIME_NTRULPR953_X25519("NTRULPRIME/ntrulpr953+X25519", NTRULPRIME_NTRULPR953, "X25519"),
    @SerializedName("NTRULPRIME/ntrulpr953+X448")
    NTRULPRIME_NTRULPR953_X448("NTRULPRIME/ntrulpr953+X448", NTRULPRIME_NTRULPR953, "X448"),
    @SerializedName("NTRULPRIME/ntrulpr1013+X25519")
    NTRULPRIME_NTRULPR1013_X25519("NTRULPRIME/ntrulpr1013+X25519", NTRULPRIME_NTRULPR1013, "X25519"),
    @SerializedName("NTRULPRIME/ntrulpr1013+X448")
    NTRULPRIME_NTRULPR1013_X448("NTRULPRIME/ntrulpr1013+X448", NTRULPRIME_NTRULPR1013, "X448"),
    @SerializedName("NTRULPRIME/ntrulpr1277+X25519")
    NTRULPRIME_NTRULPR1277_X25519("NTRULPRIME/ntrulpr1277+X25519", NTRULPRIME_NTRULPR1277, "X25519"),
    @SerializedName("NTRULPRIME/ntrulpr1277+X448")
    NTRULPRIME_NTRULPR1277_X448("NTRULPRIME/ntrulpr1277+X448", NTRULPRIME_NTRULPR1277, "X448"),
    @SerializedName("SNTRUPRIME/sntrup653+X25519")
    SNTRUPRIME_SNTRUP653_X25519("SNTRUPRIME/sntrup653+X25519", SNTRUPRIME_SNTRUP653, "X25519"),
    @SerializedName("SNTRUPRIME/sntrup653+X448")
    SNTRUPRIME_SNTRUP653_X448("SNTRUPRIME/sntrup653+X448", SNTRUPRIME_SNTRUP653, "X448"),
    @SerializedName("SNTRUPRIME/sntrup761+X25519")
    SNTRUPRIME_SNTRUP761_X25519("SNTRUPRIME/sntrup761+X25519", SNTRUPRIME_SNTRUP761, "X25519"),
    @SerializedName("SNTRUPRIME/sntrup761+X448")
    SNTRUPRIME_SNTRUP761_X448("SNTRUPRIME/sntrup761+X448", SNTRUPRIME_SNTRUP761, "X448"),
    @SerializedName("SNTRUPRIME/sntrup857+X25519")
    SNTRUPRIME_SNTRUP857_X25519("SNTRUPRIME/sntrup857+X25519", SNTRUPRIME_SNTRUP857, "X25519"),
    @SerializedName("SNTRUPRIME/sntrup857+X448")
    SNTRUPRIME_SNTRUP857_X448("SNTRUPRIME/sntrup857+X448", SNTRUPRIME_SNTRUP857, "X448"),
    @SerializedName("SNTRUPRIME/sntrup953+X25519")
    SNTRUPRIME_SNTRUP953_X25519("SNTRUPRIME/sntrup953+X25519", SNTRUPRIME_SNTRUP953, "X25519"),
    @SerializedName("SNTRUPRIME/sntrup953+X448")
    SNTRUPRIME_SNTRUP953_X448("SNTRUPRIME/sntrup953+X448", SNTRUPRIME_SNTRUP953, "X448"),
    @SerializedName("SNTRUPRIME/sntrup1013+X25519")
    SNTRUPRIME_SNTRUP1013_X25519("SNTRUPRIME/sntrup1013+X25519", SNTRUPRIME_SNTRUP1013, "X25519"),
    @SerializedName("SNTRUPRIME/sntrup1013+X448")
    SNTRUPRIME_SNTRUP1013_X448("SNTRUPRIME/sntrup1013+X448", SNTRUPRIME_SNTRUP1013, "X448"),
    @SerializedName("SNTRUPRIME/sntrup1277+X25519")
    SNTRUPRIME_SNTRUP1277_X25519("SNTRUPRIME/sntrup1277+X25519", SNTRUPRIME_SNTRUP1277, "X25519"),
    @SerializedName("SNTRUPRIME/sntrup1277+X448")
    SNTRUPRIME_SNTRUP1277_X448("SNTRUPRIME/sntrup1277+X448", SNTRUPRIME_SNTRUP1277, "X448"),
    @SerializedName("ML-KEM-512+X25519")
    ML_KEM_512_X25519("ML-KEM-512+X25519", ML_KEM_512, "X25519"),
    @SerializedName("ML-KEM-512+X448")
    ML_KEM_512_X448("ML-KEM-512+X448", ML_KEM_512, "X448"),
    @SerializedName("ML-KEM-768+X25519")
    ML_KEM_768_X25519("ML-KEM-768+X25519", ML_KEM_768, "X25519"),
    @SerializedName("ML-KEM-768+X448")
    ML_KEM_768_X448("ML-KEM-768+X448", ML_KEM_768, "X448"),
    @SerializedName("ML-KEM-1024+X25519")
    ML_KEM_1024_X25519("ML-KEM-1024+X25519", ML_KEM_1024, "X25519"),
    @SerializedName("ML-KEM-1024+X448")
    ML_KEM_1024_X448("ML-KEM-1024+X448", ML_KEM_1024, "X448");

    private final String identifier;
    private final String jcaName;
    private final String provider;
    private final AlgorithmParameterSpec parameterSpec;
    private final KemAlgorithm postQuantumComponent;
    private final String classicalAlgorithm;
    private final boolean nativeHybrid;

    /**
     * Creates a kem algorithm with the supplied dependencies and initial state.
     *
     * @param identifier the identifier supplied to this operation
     * @param jcaName the jca name supplied to this operation
     * @param provider the explicitly selected JCA provider name
     * @param parameterSpec the parameter spec supplied to this operation
     */
    KemAlgorithm(String identifier, String jcaName, String provider, AlgorithmParameterSpec parameterSpec) {
        this.identifier = identifier;
        this.jcaName = jcaName;
        this.provider = provider;
        this.parameterSpec = parameterSpec;
        this.postQuantumComponent = null;
        this.classicalAlgorithm = null;
        this.nativeHybrid = false;
    }

    /**
     * Creates a kem algorithm with the supplied dependencies and initial state.
     *
     * @param identifier the identifier supplied to this operation
     * @param postQuantumComponent the post quantum component supplied to this operation
     * @param classicalAlgorithm the classical algorithm supplied to this operation
     */
    KemAlgorithm(String identifier, KemAlgorithm postQuantumComponent, String classicalAlgorithm) {
        this.identifier = identifier;
        this.jcaName = postQuantumComponent.identifier.equals("ML-KEM-768") && classicalAlgorithm.equals("X25519")
                ? "MLKEM768-X25519-SHA3-256"
                : postQuantumComponent.identifier.equals("ML-KEM-1024") && classicalAlgorithm.equals("X448")
                ? "MLKEM1024-X448-SHA3-256" : postQuantumComponent.jcaName;
        this.nativeHybrid = !jcaName.equals(postQuantumComponent.jcaName);
        this.provider = nativeHybrid ? "BC" : postQuantumComponent.provider;
        this.parameterSpec = nativeHybrid ? null : postQuantumComponent.parameterSpec;
        this.postQuantumComponent = postQuantumComponent;
        this.classicalAlgorithm = classicalAlgorithm;
    }

    /**
     * Returns the classical algorithm value used by the kem algorithm.
     *
     * @return the result described above
     */
    public String classicalAlgorithm() {
        return classicalAlgorithm;
    }

    /**
     * Returns the native hybrid value used by the kem algorithm.
     *
     * @return whether the condition or operation described above succeeds
     */
    public boolean nativeHybrid() {
        return nativeHybrid;
    }

    /**
     * Returns the hybrid value used by the kem algorithm.
     *
     * @return whether the condition or operation described above succeeds
     */
    public boolean hybrid() {
        return postQuantumComponent != null;
    }

    /**
     * Returns the post quantum component value used by the kem algorithm.
     *
     * @return the result described above
     */
    public KemAlgorithm postQuantumComponent() {
        return hybrid() ? postQuantumComponent : this;
    }

    /**
     * Returns the identifier value used by the kem algorithm.
     *
     * @return the result described above
     */
    public String identifier() {
        return identifier;
    }

    /**
     * Returns the jca name value used by the kem algorithm.
     *
     * @return the result described above
     */
    public String jcaName() {
        return jcaName;
    }

    /**
     * Returns the provider value used by the kem algorithm.
     *
     * @return the result described above
     */
    public String provider() {
        return provider;
    }

    /**
     * Returns the parameter spec value used by the kem algorithm.
     *
     * @return the result described above
     */
    public AlgorithmParameterSpec parameterSpec() {
        return parameterSpec;
    }

    /**
     * Resolves the supplied values into the definition used by the kem algorithm.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     */
    public static KemAlgorithm fromIdentifier(String value) {
        String normalized = withoutKeyRole(value);
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.identifier.equalsIgnoreCase(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported KEM algorithm: " + value));
    }

    /**
     * Returns a value with the supplied out key role while retaining the other recorded fields.
     *
     * @param value the value supplied to this operation
     * @return the result described above
     */
    private static String withoutKeyRole(String value) {
        if (value == null) {
            throw new IllegalArgumentException("KEM algorithm is missing");
        }
        String normalized = value.trim();
        String lower = normalized.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith("/public")) {
            return normalized.substring(0, normalized.length() - 7);
        }
        if (lower.endsWith("/private")) {
            return normalized.substring(0, normalized.length() - 8);
        }
        return normalized;
    }
}
