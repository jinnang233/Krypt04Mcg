package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public enum SignatureAlgorithm {
    @SerializedName("Falcon-512")
    FALCON_512("Falcon-512", "Falcon", "BCPQC", FalconParameterSpec.falcon_512),
    @SerializedName("Falcon-1024")
    FALCON_1024("Falcon-1024", "Falcon", "BCPQC", FalconParameterSpec.falcon_1024),
    @SerializedName("ML-DSA-44")
    ML_DSA_44("ML-DSA-44", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_44),
    @SerializedName("ML-DSA-65")
    ML_DSA_65("ML-DSA-65", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_65),
    @SerializedName("ML-DSA-87")
    ML_DSA_87("ML-DSA-87", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_87),
    @SerializedName("SLH-DSA-SHA2-128F")
    SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_128f),
    @SerializedName("SLH-DSA-SHA2-128S")
    SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_128s),
    @SerializedName("SLH-DSA-SHA2-192F")
    SLH_DSA_SHA2_192F("SLH-DSA-SHA2-192F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_192f),
    @SerializedName("SLH-DSA-SHA2-192S")
    SLH_DSA_SHA2_192S("SLH-DSA-SHA2-192S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_192s),
    @SerializedName("SLH-DSA-SHA2-256F")
    SLH_DSA_SHA2_256F("SLH-DSA-SHA2-256F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_256f),
    @SerializedName("SLH-DSA-SHA2-256S")
    SLH_DSA_SHA2_256S("SLH-DSA-SHA2-256S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_256s),
    @SerializedName("SLH-DSA-SHAKE-128F")
    SLH_DSA_SHAKE_128F("SLH-DSA-SHAKE-128F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_128f),
    @SerializedName("SLH-DSA-SHAKE-128S")
    SLH_DSA_SHAKE_128S("SLH-DSA-SHAKE-128S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_128s),
    @SerializedName("SLH-DSA-SHAKE-192F")
    SLH_DSA_SHAKE_192F("SLH-DSA-SHAKE-192F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_192f),
    @SerializedName("SLH-DSA-SHAKE-192S")
    SLH_DSA_SHAKE_192S("SLH-DSA-SHAKE-192S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_192s),
    @SerializedName("SLH-DSA-SHAKE-256F")
    SLH_DSA_SHAKE_256F("SLH-DSA-SHAKE-256F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_256f),
    @SerializedName("SLH-DSA-SHAKE-256S")
    SLH_DSA_SHAKE_256S("SLH-DSA-SHAKE-256S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_256s),
    @SerializedName("SLH-DSA-SHA2-128F-WITH-SHA256")
    SLH_DSA_SHA2_128F_WITH_SHA256("SLH-DSA-SHA2-128F-WITH-SHA256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256),
    @SerializedName("SLH-DSA-SHA2-128S-WITH-SHA256")
    SLH_DSA_SHA2_128S_WITH_SHA256("SLH-DSA-SHA2-128S-WITH-SHA256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256),
    @SerializedName("SLH-DSA-SHA2-192F-WITH-SHA512")
    SLH_DSA_SHA2_192F_WITH_SHA512("SLH-DSA-SHA2-192F-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512),
    @SerializedName("SLH-DSA-SHA2-192S-WITH-SHA512")
    SLH_DSA_SHA2_192S_WITH_SHA512("SLH-DSA-SHA2-192S-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512),
    @SerializedName("SLH-DSA-SHA2-256F-WITH-SHA512")
    SLH_DSA_SHA2_256F_WITH_SHA512("SLH-DSA-SHA2-256F-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512),
    @SerializedName("SLH-DSA-SHA2-256S-WITH-SHA512")
    SLH_DSA_SHA2_256S_WITH_SHA512("SLH-DSA-SHA2-256S-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512),
    @SerializedName("SLH-DSA-SHAKE-128F-WITH-SHAKE128")
    SLH_DSA_SHAKE_128F_WITH_SHAKE128("SLH-DSA-SHAKE-128F-WITH-SHAKE128", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128),
    @SerializedName("SLH-DSA-SHAKE-128S-WITH-SHAKE128")
    SLH_DSA_SHAKE_128S_WITH_SHAKE128("SLH-DSA-SHAKE-128S-WITH-SHAKE128", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128),
    @SerializedName("SLH-DSA-SHAKE-192F-WITH-SHAKE256")
    SLH_DSA_SHAKE_192F_WITH_SHAKE256("SLH-DSA-SHAKE-192F-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256),
    @SerializedName("SLH-DSA-SHAKE-192S-WITH-SHAKE256")
    SLH_DSA_SHAKE_192S_WITH_SHAKE256("SLH-DSA-SHAKE-192S-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256),
    @SerializedName("SLH-DSA-SHAKE-256F-WITH-SHAKE256")
    SLH_DSA_SHAKE_256F_WITH_SHAKE256("SLH-DSA-SHAKE-256F-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256),
    @SerializedName("SLH-DSA-SHAKE-256S-WITH-SHAKE256")
    SLH_DSA_SHAKE_256S_WITH_SHAKE256("SLH-DSA-SHAKE-256S-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256),
    @SerializedName("SQIsign-lvl1")
    SQISIGN_LVL1("SQIsign-lvl1", "sqisign_lvl1", "BCPQC", SQIsignParameterSpec.sqisign_lvl1),
    @SerializedName("SQIsign-lvl3")
    SQISIGN_LVL3("SQIsign-lvl3", "sqisign_lvl3", "BCPQC", SQIsignParameterSpec.sqisign_lvl3),
    @SerializedName("SQIsign-lvl5")
    SQISIGN_LVL5("SQIsign-lvl5", "sqisign_lvl5", "BCPQC", SQIsignParameterSpec.sqisign_lvl5),
    @SerializedName("SNOVA-24-5-4-SSK")
    SNOVA_24_5_4_SSK("SNOVA-24-5-4-SSK", "SNOVA_24_5_4_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_4_SSK),
    @SerializedName("SNOVA-24-5-4-ESK")
    SNOVA_24_5_4_ESK("SNOVA-24-5-4-ESK", "SNOVA_24_5_4_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_4_ESK),
    @SerializedName("SNOVA-24-5-4-SHAKE-SSK")
    SNOVA_24_5_4_SHAKE_SSK("SNOVA-24-5-4-SHAKE-SSK", "SNOVA_24_5_4_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_4_SHAKE_SSK),
    @SerializedName("SNOVA-24-5-4-SHAKE-ESK")
    SNOVA_24_5_4_SHAKE_ESK("SNOVA-24-5-4-SHAKE-ESK", "SNOVA_24_5_4_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_4_SHAKE_ESK),
    @SerializedName("SNOVA-24-5-5-SSK")
    SNOVA_24_5_5_SSK("SNOVA-24-5-5-SSK", "SNOVA_24_5_5_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_5_SSK),
    @SerializedName("SNOVA-24-5-5-ESK")
    SNOVA_24_5_5_ESK("SNOVA-24-5-5-ESK", "SNOVA_24_5_5_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_5_ESK),
    @SerializedName("SNOVA-24-5-5-SHAKE-SSK")
    SNOVA_24_5_5_SHAKE_SSK("SNOVA-24-5-5-SHAKE-SSK", "SNOVA_24_5_5_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_5_SHAKE_SSK),
    @SerializedName("SNOVA-24-5-5-SHAKE-ESK")
    SNOVA_24_5_5_SHAKE_ESK("SNOVA-24-5-5-SHAKE-ESK", "SNOVA_24_5_5_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_24_5_5_SHAKE_ESK),
    @SerializedName("SNOVA-25-8-3-SSK")
    SNOVA_25_8_3_SSK("SNOVA-25-8-3-SSK", "SNOVA_25_8_3_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_25_8_3_SSK),
    @SerializedName("SNOVA-25-8-3-ESK")
    SNOVA_25_8_3_ESK("SNOVA-25-8-3-ESK", "SNOVA_25_8_3_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_25_8_3_ESK),
    @SerializedName("SNOVA-25-8-3-SHAKE-SSK")
    SNOVA_25_8_3_SHAKE_SSK("SNOVA-25-8-3-SHAKE-SSK", "SNOVA_25_8_3_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_25_8_3_SHAKE_SSK),
    @SerializedName("SNOVA-25-8-3-SHAKE-ESK")
    SNOVA_25_8_3_SHAKE_ESK("SNOVA-25-8-3-SHAKE-ESK", "SNOVA_25_8_3_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_25_8_3_SHAKE_ESK),
    @SerializedName("SNOVA-29-6-5-SSK")
    SNOVA_29_6_5_SSK("SNOVA-29-6-5-SSK", "SNOVA_29_6_5_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_29_6_5_SSK),
    @SerializedName("SNOVA-29-6-5-ESK")
    SNOVA_29_6_5_ESK("SNOVA-29-6-5-ESK", "SNOVA_29_6_5_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_29_6_5_ESK),
    @SerializedName("SNOVA-29-6-5-SHAKE-SSK")
    SNOVA_29_6_5_SHAKE_SSK("SNOVA-29-6-5-SHAKE-SSK", "SNOVA_29_6_5_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_29_6_5_SHAKE_SSK),
    @SerializedName("SNOVA-29-6-5-SHAKE-ESK")
    SNOVA_29_6_5_SHAKE_ESK("SNOVA-29-6-5-SHAKE-ESK", "SNOVA_29_6_5_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_29_6_5_SHAKE_ESK),
    @SerializedName("SNOVA-37-8-4-SSK")
    SNOVA_37_8_4_SSK("SNOVA-37-8-4-SSK", "SNOVA_37_8_4_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_8_4_SSK),
    @SerializedName("SNOVA-37-8-4-ESK")
    SNOVA_37_8_4_ESK("SNOVA-37-8-4-ESK", "SNOVA_37_8_4_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_8_4_ESK),
    @SerializedName("SNOVA-37-8-4-SHAKE-SSK")
    SNOVA_37_8_4_SHAKE_SSK("SNOVA-37-8-4-SHAKE-SSK", "SNOVA_37_8_4_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_8_4_SHAKE_SSK),
    @SerializedName("SNOVA-37-8-4-SHAKE-ESK")
    SNOVA_37_8_4_SHAKE_ESK("SNOVA-37-8-4-SHAKE-ESK", "SNOVA_37_8_4_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_8_4_SHAKE_ESK),
    @SerializedName("SNOVA-37-17-2-SSK")
    SNOVA_37_17_2_SSK("SNOVA-37-17-2-SSK", "SNOVA_37_17_2_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_17_2_SSK),
    @SerializedName("SNOVA-37-17-2-ESK")
    SNOVA_37_17_2_ESK("SNOVA-37-17-2-ESK", "SNOVA_37_17_2_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_17_2_ESK),
    @SerializedName("SNOVA-37-17-2-SHAKE-SSK")
    SNOVA_37_17_2_SHAKE_SSK("SNOVA-37-17-2-SHAKE-SSK", "SNOVA_37_17_2_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_17_2_SHAKE_SSK),
    @SerializedName("SNOVA-37-17-2-SHAKE-ESK")
    SNOVA_37_17_2_SHAKE_ESK("SNOVA-37-17-2-SHAKE-ESK", "SNOVA_37_17_2_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_37_17_2_SHAKE_ESK),
    @SerializedName("SNOVA-49-11-3-SSK")
    SNOVA_49_11_3_SSK("SNOVA-49-11-3-SSK", "SNOVA_49_11_3_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_49_11_3_SSK),
    @SerializedName("SNOVA-49-11-3-ESK")
    SNOVA_49_11_3_ESK("SNOVA-49-11-3-ESK", "SNOVA_49_11_3_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_49_11_3_ESK),
    @SerializedName("SNOVA-49-11-3-SHAKE-SSK")
    SNOVA_49_11_3_SHAKE_SSK("SNOVA-49-11-3-SHAKE-SSK", "SNOVA_49_11_3_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_49_11_3_SHAKE_SSK),
    @SerializedName("SNOVA-49-11-3-SHAKE-ESK")
    SNOVA_49_11_3_SHAKE_ESK("SNOVA-49-11-3-SHAKE-ESK", "SNOVA_49_11_3_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_49_11_3_SHAKE_ESK),
    @SerializedName("SNOVA-56-25-2-SSK")
    SNOVA_56_25_2_SSK("SNOVA-56-25-2-SSK", "SNOVA_56_25_2_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_56_25_2_SSK),
    @SerializedName("SNOVA-56-25-2-ESK")
    SNOVA_56_25_2_ESK("SNOVA-56-25-2-ESK", "SNOVA_56_25_2_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_56_25_2_ESK),
    @SerializedName("SNOVA-56-25-2-SHAKE-SSK")
    SNOVA_56_25_2_SHAKE_SSK("SNOVA-56-25-2-SHAKE-SSK", "SNOVA_56_25_2_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_56_25_2_SHAKE_SSK),
    @SerializedName("SNOVA-56-25-2-SHAKE-ESK")
    SNOVA_56_25_2_SHAKE_ESK("SNOVA-56-25-2-SHAKE-ESK", "SNOVA_56_25_2_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_56_25_2_SHAKE_ESK),
    @SerializedName("SNOVA-60-10-4-SSK")
    SNOVA_60_10_4_SSK("SNOVA-60-10-4-SSK", "SNOVA_60_10_4_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_60_10_4_SSK),
    @SerializedName("SNOVA-60-10-4-ESK")
    SNOVA_60_10_4_ESK("SNOVA-60-10-4-ESK", "SNOVA_60_10_4_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_60_10_4_ESK),
    @SerializedName("SNOVA-60-10-4-SHAKE-SSK")
    SNOVA_60_10_4_SHAKE_SSK("SNOVA-60-10-4-SHAKE-SSK", "SNOVA_60_10_4_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_60_10_4_SHAKE_SSK),
    @SerializedName("SNOVA-60-10-4-SHAKE-ESK")
    SNOVA_60_10_4_SHAKE_ESK("SNOVA-60-10-4-SHAKE-ESK", "SNOVA_60_10_4_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_60_10_4_SHAKE_ESK),
    @SerializedName("SNOVA-66-15-3-SSK")
    SNOVA_66_15_3_SSK("SNOVA-66-15-3-SSK", "SNOVA_66_15_3_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_66_15_3_SSK),
    @SerializedName("SNOVA-66-15-3-ESK")
    SNOVA_66_15_3_ESK("SNOVA-66-15-3-ESK", "SNOVA_66_15_3_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_66_15_3_ESK),
    @SerializedName("SNOVA-66-15-3-SHAKE-SSK")
    SNOVA_66_15_3_SHAKE_SSK("SNOVA-66-15-3-SHAKE-SSK", "SNOVA_66_15_3_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_66_15_3_SHAKE_SSK),
    @SerializedName("SNOVA-66-15-3-SHAKE-ESK")
    SNOVA_66_15_3_SHAKE_ESK("SNOVA-66-15-3-SHAKE-ESK", "SNOVA_66_15_3_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_66_15_3_SHAKE_ESK),
    @SerializedName("SNOVA-75-33-2-SSK")
    SNOVA_75_33_2_SSK("SNOVA-75-33-2-SSK", "SNOVA_75_33_2_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_75_33_2_SSK),
    @SerializedName("SNOVA-75-33-2-ESK")
    SNOVA_75_33_2_ESK("SNOVA-75-33-2-ESK", "SNOVA_75_33_2_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_75_33_2_ESK),
    @SerializedName("SNOVA-75-33-2-SHAKE-SSK")
    SNOVA_75_33_2_SHAKE_SSK("SNOVA-75-33-2-SHAKE-SSK", "SNOVA_75_33_2_SHAKE_SSK", "BCPQC",
            SnovaParameterSpec.SNOVA_75_33_2_SHAKE_SSK),
    @SerializedName("SNOVA-75-33-2-SHAKE-ESK")
    SNOVA_75_33_2_SHAKE_ESK("SNOVA-75-33-2-SHAKE-ESK", "SNOVA_75_33_2_SHAKE_ESK", "BCPQC",
            SnovaParameterSpec.SNOVA_75_33_2_SHAKE_ESK);

    private final String identifier;
    private final String jcaName;
    private final String provider;
    private final AlgorithmParameterSpec parameterSpec;

    SignatureAlgorithm(String identifier, String jcaName, String provider, AlgorithmParameterSpec parameterSpec) {
        this.identifier = identifier;
        this.jcaName = jcaName;
        this.provider = provider;
        this.parameterSpec = parameterSpec;
    }

    public String identifier() {
        return identifier;
    }

    public String jcaName() {
        return jcaName;
    }

    public String provider() {
        return provider;
    }

    public AlgorithmParameterSpec parameterSpec() {
        return parameterSpec;
    }

    public static SignatureAlgorithm fromIdentifier(String value) {
        String normalized = withoutKeyRole(value);
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.identifier.equalsIgnoreCase(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported signature algorithm: " + value));
    }

    private static String withoutKeyRole(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Signature algorithm is missing");
        }
        String normalized = value.trim();
        if (normalized.toLowerCase(java.util.Locale.ROOT).endsWith("/public")) {
            return normalized.substring(0, normalized.length() - 7);
        }
        if (normalized.toLowerCase(java.util.Locale.ROOT).endsWith("/private")) {
            return normalized.substring(0, normalized.length() - 8);
        }
        return normalized;
    }
}
