package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
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
            SnovaParameterSpec.SNOVA_75_33_2_SHAKE_ESK),
    @SerializedName("MLDSA44-ECDSA-P256-SHA256")
    MLDSA44_ECDSA_P256_SHA256("MLDSA44-ECDSA-P256-SHA256", "MLDSA44-ECDSA-P256-SHA256", "BC", null),
    @SerializedName("MLDSA44-Ed25519-SHA512")
    MLDSA44_ED25519_SHA512("MLDSA44-Ed25519-SHA512", "MLDSA44-Ed25519-SHA512", "BC", null),
    @SerializedName("MLDSA44-RSA2048-PKCS15-SHA256")
    MLDSA44_RSA2048_PKCS15_SHA256("MLDSA44-RSA2048-PKCS15-SHA256", "MLDSA44-RSA2048-PKCS15-SHA256", "BC", null),
    @SerializedName("MLDSA44-RSA2048-PSS-SHA256")
    MLDSA44_RSA2048_PSS_SHA256("MLDSA44-RSA2048-PSS-SHA256", "MLDSA44-RSA2048-PSS-SHA256", "BC", null),
    @SerializedName("MLDSA65-ECDSA-P256-SHA512")
    MLDSA65_ECDSA_P256_SHA512("MLDSA65-ECDSA-P256-SHA512", "MLDSA65-ECDSA-P256-SHA512", "BC", null),
    @SerializedName("MLDSA65-ECDSA-P384-SHA512")
    MLDSA65_ECDSA_P384_SHA512("MLDSA65-ECDSA-P384-SHA512", "MLDSA65-ECDSA-P384-SHA512", "BC", null),
    @SerializedName("MLDSA65-ECDSA-brainpoolP256r1-SHA512")
    MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512("MLDSA65-ECDSA-brainpoolP256r1-SHA512", "MLDSA65-ECDSA-brainpoolP256r1-SHA512", "BC", null),
    @SerializedName("MLDSA65-Ed25519-SHA512")
    MLDSA65_ED25519_SHA512("MLDSA65-Ed25519-SHA512", "MLDSA65-Ed25519-SHA512", "BC", null),
    @SerializedName("MLDSA65-RSA3072-PKCS15-SHA512")
    MLDSA65_RSA3072_PKCS15_SHA512("MLDSA65-RSA3072-PKCS15-SHA512", "MLDSA65-RSA3072-PKCS15-SHA512", "BC", null),
    @SerializedName("MLDSA65-RSA3072-PSS-SHA512")
    MLDSA65_RSA3072_PSS_SHA512("MLDSA65-RSA3072-PSS-SHA512", "MLDSA65-RSA3072-PSS-SHA512", "BC", null),
    @SerializedName("MLDSA65-RSA4096-PKCS15-SHA512")
    MLDSA65_RSA4096_PKCS15_SHA512("MLDSA65-RSA4096-PKCS15-SHA512", "MLDSA65-RSA4096-PKCS15-SHA512", "BC", null),
    @SerializedName("MLDSA65-RSA4096-PSS-SHA512")
    MLDSA65_RSA4096_PSS_SHA512("MLDSA65-RSA4096-PSS-SHA512", "MLDSA65-RSA4096-PSS-SHA512", "BC", null),
    @SerializedName("MLDSA87-ECDSA-P384-SHA512")
    MLDSA87_ECDSA_P384_SHA512("MLDSA87-ECDSA-P384-SHA512", "MLDSA87-ECDSA-P384-SHA512", "BC", null),
    @SerializedName("MLDSA87-ECDSA-P521-SHA512")
    MLDSA87_ECDSA_P521_SHA512("MLDSA87-ECDSA-P521-SHA512", "MLDSA87-ECDSA-P521-SHA512", "BC", null),
    @SerializedName("MLDSA87-ECDSA-brainpoolP384r1-SHA512")
    MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512("MLDSA87-ECDSA-brainpoolP384r1-SHA512", "MLDSA87-ECDSA-brainpoolP384r1-SHA512", "BC", null),
    @SerializedName("MLDSA87-Ed448-SHAKE256")
    MLDSA87_ED448_SHAKE256("MLDSA87-Ed448-SHAKE256", "MLDSA87-Ed448-SHAKE256", "BC", null),
    @SerializedName("MLDSA87-RSA3072-PSS-SHA512")
    MLDSA87_RSA3072_PSS_SHA512("MLDSA87-RSA3072-PSS-SHA512", "MLDSA87-RSA3072-PSS-SHA512", "BC", null),
    @SerializedName("MLDSA87-RSA4096-PSS-SHA512")
    MLDSA87_RSA4096_PSS_SHA512("MLDSA87-RSA4096-PSS-SHA512", "MLDSA87-RSA4096-PSS-SHA512", "BC", null),
    @SerializedName("MAYO-1")
    MAYO_1("MAYO-1", "Mayo", "BCPQC", MayoParameterSpec.mayo1),
    @SerializedName("MAYO-2")
    MAYO_2("MAYO-2", "Mayo", "BCPQC", MayoParameterSpec.mayo2),
    @SerializedName("MAYO-3")
    MAYO_3("MAYO-3", "Mayo", "BCPQC", MayoParameterSpec.mayo3),
    @SerializedName("MAYO-5")
    MAYO_5("MAYO-5", "Mayo", "BCPQC", MayoParameterSpec.mayo5),
    @SerializedName("HAETAE-2")
    HAETAE_2("HAETAE-2", "Haetae", "BCPQC", HaetaeParameterSpec.haetae2),
    @SerializedName("HAETAE-3")
    HAETAE_3("HAETAE-3", "Haetae", "BCPQC", HaetaeParameterSpec.haetae3),
    @SerializedName("HAETAE-5")
    HAETAE_5("HAETAE-5", "Haetae", "BCPQC", HaetaeParameterSpec.haetae5),
    @SerializedName("UOV-IS")
    UOV_IS("UOV-IS", "UOV", "BCPQC", UOVParameterSpec.uov_Is),
    @SerializedName("UOV-IS-PKC")
    UOV_IS_PKC("UOV-IS-PKC", "UOV", "BCPQC", UOVParameterSpec.uov_Is_pkc),
    @SerializedName("UOV-IS-PKC-SKC")
    UOV_IS_PKC_SKC("UOV-IS-PKC-SKC", "UOV", "BCPQC", UOVParameterSpec.uov_Is_pkc_skc),
    @SerializedName("UOV-IP")
    UOV_IP("UOV-IP", "UOV", "BCPQC", UOVParameterSpec.uov_Ip),
    @SerializedName("UOV-IP-PKC")
    UOV_IP_PKC("UOV-IP-PKC", "UOV", "BCPQC", UOVParameterSpec.uov_Ip_pkc),
    @SerializedName("UOV-IP-PKC-SKC")
    UOV_IP_PKC_SKC("UOV-IP-PKC-SKC", "UOV", "BCPQC", UOVParameterSpec.uov_Ip_pkc_skc),
    @SerializedName("UOV-III")
    UOV_III("UOV-III", "UOV", "BCPQC", UOVParameterSpec.uov_III),
    @SerializedName("UOV-III-PKC")
    UOV_III_PKC("UOV-III-PKC", "UOV", "BCPQC", UOVParameterSpec.uov_III_pkc),
    @SerializedName("UOV-III-PKC-SKC")
    UOV_III_PKC_SKC("UOV-III-PKC-SKC", "UOV", "BCPQC", UOVParameterSpec.uov_III_pkc_skc),
    @SerializedName("UOV-V")
    UOV_V("UOV-V", "UOV", "BCPQC", UOVParameterSpec.uov_V),
    @SerializedName("UOV-V-PKC")
    UOV_V_PKC("UOV-V-PKC", "UOV", "BCPQC", UOVParameterSpec.uov_V_pkc),
    @SerializedName("UOV-V-PKC-SKC")
    UOV_V_PKC_SKC("UOV-V-PKC-SKC", "UOV", "BCPQC", UOVParameterSpec.uov_V_pkc_skc),
    @SerializedName("QR-UOV/qruov1q127L3v156m54")
    QRUOV_1Q127L3V156M54("QR-UOV/qruov1q127L3v156m54", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov1q127L3v156m54),
    @SerializedName("QR-UOV/qruov1q31L3v165m60")
    QRUOV_1Q31L3V165M60("QR-UOV/qruov1q31L3v165m60", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov1q31L3v165m60),
    @SerializedName("QR-UOV/qruov1q31L10v600m70")
    QRUOV_1Q31L10V600M70("QR-UOV/qruov1q31L10v600m70", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov1q31L10v600m70),
    @SerializedName("QR-UOV/qruov1q7L10v740m100")
    QRUOV_1Q7L10V740M100("QR-UOV/qruov1q7L10v740m100", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov1q7L10v740m100),
    @SerializedName("QR-UOV/qruov3q127L3v228m78")
    QRUOV_3Q127L3V228M78("QR-UOV/qruov3q127L3v228m78", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov3q127L3v228m78),
    @SerializedName("QR-UOV/qruov3q31L3v246m87")
    QRUOV_3Q31L3V246M87("QR-UOV/qruov3q31L3v246m87", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov3q31L3v246m87),
    @SerializedName("QR-UOV/qruov3q31L10v890m100")
    QRUOV_3Q31L10V890M100("QR-UOV/qruov3q31L10v890m100", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov3q31L10v890m100),
    @SerializedName("QR-UOV/qruov3q7L10v1100m140")
    QRUOV_3Q7L10V1100M140("QR-UOV/qruov3q7L10v1100m140", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov3q7L10v1100m140),
    @SerializedName("QR-UOV/qruov5q127L3v306m105")
    QRUOV_5Q127L3V306M105("QR-UOV/qruov5q127L3v306m105", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov5q127L3v306m105),
    @SerializedName("QR-UOV/qruov5q31L3v324m114")
    QRUOV_5Q31L3V324M114("QR-UOV/qruov5q31L3v324m114", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov5q31L3v324m114),
    @SerializedName("QR-UOV/qruov5q31L10v1120m120")
    QRUOV_5Q31L10V1120M120("QR-UOV/qruov5q31L10v1120m120", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov5q31L10v1120m120),
    @SerializedName("QR-UOV/qruov5q7L10v1490m190")
    QRUOV_5Q7L10V1490M190("QR-UOV/qruov5q7L10v1490m190", "QRUOV", "BCPQC", QRUOVParameterSpec.qruov5q7L10v1490m190),
    @SerializedName("AIMer-128f")
    AIMER_128F("AIMer-128f", "AIMer", "BCPQC", AIMerParameterSpec.aimer128f),
    @SerializedName("AIMer-128s")
    AIMER_128S("AIMer-128s", "AIMer", "BCPQC", AIMerParameterSpec.aimer128s),
    @SerializedName("AIMer-192f")
    AIMER_192F("AIMer-192f", "AIMer", "BCPQC", AIMerParameterSpec.aimer192f),
    @SerializedName("AIMer-192s")
    AIMER_192S("AIMer-192s", "AIMer", "BCPQC", AIMerParameterSpec.aimer192s),
    @SerializedName("AIMer-256f")
    AIMER_256F("AIMer-256f", "AIMer", "BCPQC", AIMerParameterSpec.aimer256f),
    @SerializedName("AIMer-256s")
    AIMER_256S("AIMer-256s", "AIMer", "BCPQC", AIMerParameterSpec.aimer256s),
    @SerializedName("FAEST-128S")
    FAEST_128S("FAEST-128S", "Faest", "BCPQC", FaestParameterSpec.faest_128s),
    @SerializedName("FAEST-128F")
    FAEST_128F("FAEST-128F", "Faest", "BCPQC", FaestParameterSpec.faest_128f),
    @SerializedName("FAEST-192S")
    FAEST_192S("FAEST-192S", "Faest", "BCPQC", FaestParameterSpec.faest_192s),
    @SerializedName("FAEST-192F")
    FAEST_192F("FAEST-192F", "Faest", "BCPQC", FaestParameterSpec.faest_192f),
    @SerializedName("FAEST-256S")
    FAEST_256S("FAEST-256S", "Faest", "BCPQC", FaestParameterSpec.faest_256s),
    @SerializedName("FAEST-256F")
    FAEST_256F("FAEST-256F", "Faest", "BCPQC", FaestParameterSpec.faest_256f),
    @SerializedName("FAEST-EM-128S")
    FAEST_EM_128S("FAEST-EM-128S", "Faest", "BCPQC", FaestParameterSpec.faest_em_128s),
    @SerializedName("FAEST-EM-128F")
    FAEST_EM_128F("FAEST-EM-128F", "Faest", "BCPQC", FaestParameterSpec.faest_em_128f),
    @SerializedName("FAEST-EM-192S")
    FAEST_EM_192S("FAEST-EM-192S", "Faest", "BCPQC", FaestParameterSpec.faest_em_192s),
    @SerializedName("FAEST-EM-192F")
    FAEST_EM_192F("FAEST-EM-192F", "Faest", "BCPQC", FaestParameterSpec.faest_em_192f),
    @SerializedName("FAEST-EM-256S")
    FAEST_EM_256S("FAEST-EM-256S", "Faest", "BCPQC", FaestParameterSpec.faest_em_256s),
    @SerializedName("FAEST-EM-256F")
    FAEST_EM_256F("FAEST-EM-256F", "Faest", "BCPQC", FaestParameterSpec.faest_em_256f),
    @SerializedName("MQOM2-CAT1-GF2-FAST-R3")
    MQOM2_CAT1_GF2_FAST_R3("MQOM2-CAT1-GF2-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf2_fast_r3),
    @SerializedName("MQOM2-CAT1-GF2-FAST-R5")
    MQOM2_CAT1_GF2_FAST_R5("MQOM2-CAT1-GF2-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf2_fast_r5),
    @SerializedName("MQOM2-CAT1-GF2-SHORT-R3")
    MQOM2_CAT1_GF2_SHORT_R3("MQOM2-CAT1-GF2-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf2_short_r3),
    @SerializedName("MQOM2-CAT1-GF2-SHORT-R5")
    MQOM2_CAT1_GF2_SHORT_R5("MQOM2-CAT1-GF2-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf2_short_r5),
    @SerializedName("MQOM2-CAT1-GF16-FAST-R3")
    MQOM2_CAT1_GF16_FAST_R3("MQOM2-CAT1-GF16-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf16_fast_r3),
    @SerializedName("MQOM2-CAT1-GF16-FAST-R5")
    MQOM2_CAT1_GF16_FAST_R5("MQOM2-CAT1-GF16-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf16_fast_r5),
    @SerializedName("MQOM2-CAT1-GF16-SHORT-R3")
    MQOM2_CAT1_GF16_SHORT_R3("MQOM2-CAT1-GF16-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf16_short_r3),
    @SerializedName("MQOM2-CAT1-GF16-SHORT-R5")
    MQOM2_CAT1_GF16_SHORT_R5("MQOM2-CAT1-GF16-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf16_short_r5),
    @SerializedName("MQOM2-CAT1-GF256-FAST-R3")
    MQOM2_CAT1_GF256_FAST_R3("MQOM2-CAT1-GF256-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf256_fast_r3),
    @SerializedName("MQOM2-CAT1-GF256-FAST-R5")
    MQOM2_CAT1_GF256_FAST_R5("MQOM2-CAT1-GF256-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf256_fast_r5),
    @SerializedName("MQOM2-CAT1-GF256-SHORT-R3")
    MQOM2_CAT1_GF256_SHORT_R3("MQOM2-CAT1-GF256-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf256_short_r3),
    @SerializedName("MQOM2-CAT1-GF256-SHORT-R5")
    MQOM2_CAT1_GF256_SHORT_R5("MQOM2-CAT1-GF256-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat1_gf256_short_r5),
    @SerializedName("MQOM2-CAT3-GF2-FAST-R3")
    MQOM2_CAT3_GF2_FAST_R3("MQOM2-CAT3-GF2-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf2_fast_r3),
    @SerializedName("MQOM2-CAT3-GF2-FAST-R5")
    MQOM2_CAT3_GF2_FAST_R5("MQOM2-CAT3-GF2-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf2_fast_r5),
    @SerializedName("MQOM2-CAT3-GF2-SHORT-R3")
    MQOM2_CAT3_GF2_SHORT_R3("MQOM2-CAT3-GF2-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf2_short_r3),
    @SerializedName("MQOM2-CAT3-GF2-SHORT-R5")
    MQOM2_CAT3_GF2_SHORT_R5("MQOM2-CAT3-GF2-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf2_short_r5),
    @SerializedName("MQOM2-CAT3-GF16-FAST-R3")
    MQOM2_CAT3_GF16_FAST_R3("MQOM2-CAT3-GF16-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf16_fast_r3),
    @SerializedName("MQOM2-CAT3-GF16-FAST-R5")
    MQOM2_CAT3_GF16_FAST_R5("MQOM2-CAT3-GF16-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf16_fast_r5),
    @SerializedName("MQOM2-CAT3-GF16-SHORT-R3")
    MQOM2_CAT3_GF16_SHORT_R3("MQOM2-CAT3-GF16-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf16_short_r3),
    @SerializedName("MQOM2-CAT3-GF16-SHORT-R5")
    MQOM2_CAT3_GF16_SHORT_R5("MQOM2-CAT3-GF16-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf16_short_r5),
    @SerializedName("MQOM2-CAT3-GF256-FAST-R3")
    MQOM2_CAT3_GF256_FAST_R3("MQOM2-CAT3-GF256-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf256_fast_r3),
    @SerializedName("MQOM2-CAT3-GF256-FAST-R5")
    MQOM2_CAT3_GF256_FAST_R5("MQOM2-CAT3-GF256-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf256_fast_r5),
    @SerializedName("MQOM2-CAT3-GF256-SHORT-R3")
    MQOM2_CAT3_GF256_SHORT_R3("MQOM2-CAT3-GF256-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf256_short_r3),
    @SerializedName("MQOM2-CAT3-GF256-SHORT-R5")
    MQOM2_CAT3_GF256_SHORT_R5("MQOM2-CAT3-GF256-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat3_gf256_short_r5),
    @SerializedName("MQOM2-CAT5-GF2-FAST-R3")
    MQOM2_CAT5_GF2_FAST_R3("MQOM2-CAT5-GF2-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf2_fast_r3),
    @SerializedName("MQOM2-CAT5-GF2-FAST-R5")
    MQOM2_CAT5_GF2_FAST_R5("MQOM2-CAT5-GF2-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf2_fast_r5),
    @SerializedName("MQOM2-CAT5-GF2-SHORT-R3")
    MQOM2_CAT5_GF2_SHORT_R3("MQOM2-CAT5-GF2-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf2_short_r3),
    @SerializedName("MQOM2-CAT5-GF2-SHORT-R5")
    MQOM2_CAT5_GF2_SHORT_R5("MQOM2-CAT5-GF2-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf2_short_r5),
    @SerializedName("MQOM2-CAT5-GF16-FAST-R3")
    MQOM2_CAT5_GF16_FAST_R3("MQOM2-CAT5-GF16-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf16_fast_r3),
    @SerializedName("MQOM2-CAT5-GF16-FAST-R5")
    MQOM2_CAT5_GF16_FAST_R5("MQOM2-CAT5-GF16-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf16_fast_r5),
    @SerializedName("MQOM2-CAT5-GF16-SHORT-R3")
    MQOM2_CAT5_GF16_SHORT_R3("MQOM2-CAT5-GF16-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf16_short_r3),
    @SerializedName("MQOM2-CAT5-GF16-SHORT-R5")
    MQOM2_CAT5_GF16_SHORT_R5("MQOM2-CAT5-GF16-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf16_short_r5),
    @SerializedName("MQOM2-CAT5-GF256-FAST-R3")
    MQOM2_CAT5_GF256_FAST_R3("MQOM2-CAT5-GF256-FAST-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf256_fast_r3),
    @SerializedName("MQOM2-CAT5-GF256-FAST-R5")
    MQOM2_CAT5_GF256_FAST_R5("MQOM2-CAT5-GF256-FAST-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf256_fast_r5),
    @SerializedName("MQOM2-CAT5-GF256-SHORT-R3")
    MQOM2_CAT5_GF256_SHORT_R3("MQOM2-CAT5-GF256-SHORT-R3", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf256_short_r3),
    @SerializedName("MQOM2-CAT5-GF256-SHORT-R5")
    MQOM2_CAT5_GF256_SHORT_R5("MQOM2-CAT5-GF256-SHORT-R5", "MQOM", "BCPQC", MQOMParameterSpec.mqom2_cat5_gf256_short_r5),
    @SerializedName("SDITH-HYPERCUBE-CAT1-GF256")
    SDITH_HYPERCUBE_CAT1_GF256("SDITH-HYPERCUBE-CAT1-GF256", "SDitH", "BCPQC", SDitHParameterSpec.sdith_hypercube_cat1_gf256),
    @SerializedName("SDITH-HYPERCUBE-CAT3-GF256")
    SDITH_HYPERCUBE_CAT3_GF256("SDITH-HYPERCUBE-CAT3-GF256", "SDitH", "BCPQC", SDitHParameterSpec.sdith_hypercube_cat3_gf256),
    @SerializedName("SDITH-HYPERCUBE-CAT5-GF256")
    SDITH_HYPERCUBE_CAT5_GF256("SDITH-HYPERCUBE-CAT5-GF256", "SDitH", "BCPQC", SDitHParameterSpec.sdith_hypercube_cat5_gf256),
    @SerializedName("SDITH-HYPERCUBE-CAT1-P251")
    SDITH_HYPERCUBE_CAT1_P251("SDITH-HYPERCUBE-CAT1-P251", "SDitH", "BCPQC", SDitHParameterSpec.sdith_hypercube_cat1_p251),
    @SerializedName("SDITH-HYPERCUBE-CAT3-P251")
    SDITH_HYPERCUBE_CAT3_P251("SDITH-HYPERCUBE-CAT3-P251", "SDitH", "BCPQC", SDitHParameterSpec.sdith_hypercube_cat3_p251),
    @SerializedName("SDITH-HYPERCUBE-CAT5-P251")
    SDITH_HYPERCUBE_CAT5_P251("SDITH-HYPERCUBE-CAT5-P251", "SDitH", "BCPQC", SDitHParameterSpec.sdith_hypercube_cat5_p251),
    @SerializedName("SDITH-THRESHOLD-CAT1-GF256")
    SDITH_THRESHOLD_CAT1_GF256("SDITH-THRESHOLD-CAT1-GF256", "SDitH", "BCPQC", SDitHParameterSpec.sdith_threshold_cat1_gf256),
    @SerializedName("SDITH-THRESHOLD-CAT3-GF256")
    SDITH_THRESHOLD_CAT3_GF256("SDITH-THRESHOLD-CAT3-GF256", "SDitH", "BCPQC", SDitHParameterSpec.sdith_threshold_cat3_gf256),
    @SerializedName("SDITH-THRESHOLD-CAT5-GF256")
    SDITH_THRESHOLD_CAT5_GF256("SDITH-THRESHOLD-CAT5-GF256", "SDitH", "BCPQC", SDitHParameterSpec.sdith_threshold_cat5_gf256),
    @SerializedName("SDITH-THRESHOLD-CAT1-P251")
    SDITH_THRESHOLD_CAT1_P251("SDITH-THRESHOLD-CAT1-P251", "SDitH", "BCPQC", SDitHParameterSpec.sdith_threshold_cat1_p251),
    @SerializedName("SDITH-THRESHOLD-CAT3-P251")
    SDITH_THRESHOLD_CAT3_P251("SDITH-THRESHOLD-CAT3-P251", "SDitH", "BCPQC", SDitHParameterSpec.sdith_threshold_cat3_p251),
    @SerializedName("SDITH-THRESHOLD-CAT5-P251")
    SDITH_THRESHOLD_CAT5_P251("SDITH-THRESHOLD-CAT5-P251", "SDitH", "BCPQC", SDitHParameterSpec.sdith_threshold_cat5_p251),
    @SerializedName("MAYO-1+Ed25519")
    MAYO_1_ED25519("MAYO-1+Ed25519", MAYO_1, "Ed25519"),
    @SerializedName("MAYO-1+Ed448")
    MAYO_1_ED448("MAYO-1+Ed448", MAYO_1, "Ed448"),
    @SerializedName("MAYO-2+Ed25519")
    MAYO_2_ED25519("MAYO-2+Ed25519", MAYO_2, "Ed25519"),
    @SerializedName("MAYO-2+Ed448")
    MAYO_2_ED448("MAYO-2+Ed448", MAYO_2, "Ed448"),
    @SerializedName("MAYO-3+Ed25519")
    MAYO_3_ED25519("MAYO-3+Ed25519", MAYO_3, "Ed25519"),
    @SerializedName("MAYO-3+Ed448")
    MAYO_3_ED448("MAYO-3+Ed448", MAYO_3, "Ed448"),
    @SerializedName("MAYO-5+Ed25519")
    MAYO_5_ED25519("MAYO-5+Ed25519", MAYO_5, "Ed25519"),
    @SerializedName("MAYO-5+Ed448")
    MAYO_5_ED448("MAYO-5+Ed448", MAYO_5, "Ed448"),
    @SerializedName("HAETAE-2+Ed25519")
    HAETAE_2_ED25519("HAETAE-2+Ed25519", HAETAE_2, "Ed25519"),
    @SerializedName("HAETAE-2+Ed448")
    HAETAE_2_ED448("HAETAE-2+Ed448", HAETAE_2, "Ed448"),
    @SerializedName("HAETAE-3+Ed25519")
    HAETAE_3_ED25519("HAETAE-3+Ed25519", HAETAE_3, "Ed25519"),
    @SerializedName("HAETAE-3+Ed448")
    HAETAE_3_ED448("HAETAE-3+Ed448", HAETAE_3, "Ed448"),
    @SerializedName("HAETAE-5+Ed25519")
    HAETAE_5_ED25519("HAETAE-5+Ed25519", HAETAE_5, "Ed25519"),
    @SerializedName("HAETAE-5+Ed448")
    HAETAE_5_ED448("HAETAE-5+Ed448", HAETAE_5, "Ed448"),
    @SerializedName("UOV-IS+Ed25519")
    UOV_IS_ED25519("UOV-IS+Ed25519", UOV_IS, "Ed25519"),
    @SerializedName("UOV-IS+Ed448")
    UOV_IS_ED448("UOV-IS+Ed448", UOV_IS, "Ed448"),
    @SerializedName("UOV-IS-PKC+Ed25519")
    UOV_IS_PKC_ED25519("UOV-IS-PKC+Ed25519", UOV_IS_PKC, "Ed25519"),
    @SerializedName("UOV-IS-PKC+Ed448")
    UOV_IS_PKC_ED448("UOV-IS-PKC+Ed448", UOV_IS_PKC, "Ed448"),
    @SerializedName("UOV-IS-PKC-SKC+Ed25519")
    UOV_IS_PKC_SKC_ED25519("UOV-IS-PKC-SKC+Ed25519", UOV_IS_PKC_SKC, "Ed25519"),
    @SerializedName("UOV-IS-PKC-SKC+Ed448")
    UOV_IS_PKC_SKC_ED448("UOV-IS-PKC-SKC+Ed448", UOV_IS_PKC_SKC, "Ed448"),
    @SerializedName("UOV-IP+Ed25519")
    UOV_IP_ED25519("UOV-IP+Ed25519", UOV_IP, "Ed25519"),
    @SerializedName("UOV-IP+Ed448")
    UOV_IP_ED448("UOV-IP+Ed448", UOV_IP, "Ed448"),
    @SerializedName("UOV-IP-PKC+Ed25519")
    UOV_IP_PKC_ED25519("UOV-IP-PKC+Ed25519", UOV_IP_PKC, "Ed25519"),
    @SerializedName("UOV-IP-PKC+Ed448")
    UOV_IP_PKC_ED448("UOV-IP-PKC+Ed448", UOV_IP_PKC, "Ed448"),
    @SerializedName("UOV-IP-PKC-SKC+Ed25519")
    UOV_IP_PKC_SKC_ED25519("UOV-IP-PKC-SKC+Ed25519", UOV_IP_PKC_SKC, "Ed25519"),
    @SerializedName("UOV-IP-PKC-SKC+Ed448")
    UOV_IP_PKC_SKC_ED448("UOV-IP-PKC-SKC+Ed448", UOV_IP_PKC_SKC, "Ed448"),
    @SerializedName("UOV-III+Ed25519")
    UOV_III_ED25519("UOV-III+Ed25519", UOV_III, "Ed25519"),
    @SerializedName("UOV-III+Ed448")
    UOV_III_ED448("UOV-III+Ed448", UOV_III, "Ed448"),
    @SerializedName("UOV-III-PKC+Ed25519")
    UOV_III_PKC_ED25519("UOV-III-PKC+Ed25519", UOV_III_PKC, "Ed25519"),
    @SerializedName("UOV-III-PKC+Ed448")
    UOV_III_PKC_ED448("UOV-III-PKC+Ed448", UOV_III_PKC, "Ed448"),
    @SerializedName("UOV-III-PKC-SKC+Ed25519")
    UOV_III_PKC_SKC_ED25519("UOV-III-PKC-SKC+Ed25519", UOV_III_PKC_SKC, "Ed25519"),
    @SerializedName("UOV-III-PKC-SKC+Ed448")
    UOV_III_PKC_SKC_ED448("UOV-III-PKC-SKC+Ed448", UOV_III_PKC_SKC, "Ed448"),
    @SerializedName("UOV-V+Ed25519")
    UOV_V_ED25519("UOV-V+Ed25519", UOV_V, "Ed25519"),
    @SerializedName("UOV-V+Ed448")
    UOV_V_ED448("UOV-V+Ed448", UOV_V, "Ed448"),
    @SerializedName("UOV-V-PKC+Ed25519")
    UOV_V_PKC_ED25519("UOV-V-PKC+Ed25519", UOV_V_PKC, "Ed25519"),
    @SerializedName("UOV-V-PKC+Ed448")
    UOV_V_PKC_ED448("UOV-V-PKC+Ed448", UOV_V_PKC, "Ed448"),
    @SerializedName("UOV-V-PKC-SKC+Ed25519")
    UOV_V_PKC_SKC_ED25519("UOV-V-PKC-SKC+Ed25519", UOV_V_PKC_SKC, "Ed25519"),
    @SerializedName("UOV-V-PKC-SKC+Ed448")
    UOV_V_PKC_SKC_ED448("UOV-V-PKC-SKC+Ed448", UOV_V_PKC_SKC, "Ed448"),
    @SerializedName("QR-UOV/qruov1q127L3v156m54+Ed25519")
    QRUOV_1Q127L3V156M54_ED25519("QR-UOV/qruov1q127L3v156m54+Ed25519", QRUOV_1Q127L3V156M54, "Ed25519"),
    @SerializedName("QR-UOV/qruov1q127L3v156m54+Ed448")
    QRUOV_1Q127L3V156M54_ED448("QR-UOV/qruov1q127L3v156m54+Ed448", QRUOV_1Q127L3V156M54, "Ed448"),
    @SerializedName("QR-UOV/qruov1q31L3v165m60+Ed25519")
    QRUOV_1Q31L3V165M60_ED25519("QR-UOV/qruov1q31L3v165m60+Ed25519", QRUOV_1Q31L3V165M60, "Ed25519"),
    @SerializedName("QR-UOV/qruov1q31L3v165m60+Ed448")
    QRUOV_1Q31L3V165M60_ED448("QR-UOV/qruov1q31L3v165m60+Ed448", QRUOV_1Q31L3V165M60, "Ed448"),
    @SerializedName("QR-UOV/qruov1q31L10v600m70+Ed25519")
    QRUOV_1Q31L10V600M70_ED25519("QR-UOV/qruov1q31L10v600m70+Ed25519", QRUOV_1Q31L10V600M70, "Ed25519"),
    @SerializedName("QR-UOV/qruov1q31L10v600m70+Ed448")
    QRUOV_1Q31L10V600M70_ED448("QR-UOV/qruov1q31L10v600m70+Ed448", QRUOV_1Q31L10V600M70, "Ed448"),
    @SerializedName("QR-UOV/qruov1q7L10v740m100+Ed25519")
    QRUOV_1Q7L10V740M100_ED25519("QR-UOV/qruov1q7L10v740m100+Ed25519", QRUOV_1Q7L10V740M100, "Ed25519"),
    @SerializedName("QR-UOV/qruov1q7L10v740m100+Ed448")
    QRUOV_1Q7L10V740M100_ED448("QR-UOV/qruov1q7L10v740m100+Ed448", QRUOV_1Q7L10V740M100, "Ed448"),
    @SerializedName("QR-UOV/qruov3q127L3v228m78+Ed25519")
    QRUOV_3Q127L3V228M78_ED25519("QR-UOV/qruov3q127L3v228m78+Ed25519", QRUOV_3Q127L3V228M78, "Ed25519"),
    @SerializedName("QR-UOV/qruov3q127L3v228m78+Ed448")
    QRUOV_3Q127L3V228M78_ED448("QR-UOV/qruov3q127L3v228m78+Ed448", QRUOV_3Q127L3V228M78, "Ed448"),
    @SerializedName("QR-UOV/qruov3q31L3v246m87+Ed25519")
    QRUOV_3Q31L3V246M87_ED25519("QR-UOV/qruov3q31L3v246m87+Ed25519", QRUOV_3Q31L3V246M87, "Ed25519"),
    @SerializedName("QR-UOV/qruov3q31L3v246m87+Ed448")
    QRUOV_3Q31L3V246M87_ED448("QR-UOV/qruov3q31L3v246m87+Ed448", QRUOV_3Q31L3V246M87, "Ed448"),
    @SerializedName("QR-UOV/qruov3q31L10v890m100+Ed25519")
    QRUOV_3Q31L10V890M100_ED25519("QR-UOV/qruov3q31L10v890m100+Ed25519", QRUOV_3Q31L10V890M100, "Ed25519"),
    @SerializedName("QR-UOV/qruov3q31L10v890m100+Ed448")
    QRUOV_3Q31L10V890M100_ED448("QR-UOV/qruov3q31L10v890m100+Ed448", QRUOV_3Q31L10V890M100, "Ed448"),
    @SerializedName("QR-UOV/qruov3q7L10v1100m140+Ed25519")
    QRUOV_3Q7L10V1100M140_ED25519("QR-UOV/qruov3q7L10v1100m140+Ed25519", QRUOV_3Q7L10V1100M140, "Ed25519"),
    @SerializedName("QR-UOV/qruov3q7L10v1100m140+Ed448")
    QRUOV_3Q7L10V1100M140_ED448("QR-UOV/qruov3q7L10v1100m140+Ed448", QRUOV_3Q7L10V1100M140, "Ed448"),
    @SerializedName("QR-UOV/qruov5q127L3v306m105+Ed25519")
    QRUOV_5Q127L3V306M105_ED25519("QR-UOV/qruov5q127L3v306m105+Ed25519", QRUOV_5Q127L3V306M105, "Ed25519"),
    @SerializedName("QR-UOV/qruov5q127L3v306m105+Ed448")
    QRUOV_5Q127L3V306M105_ED448("QR-UOV/qruov5q127L3v306m105+Ed448", QRUOV_5Q127L3V306M105, "Ed448"),
    @SerializedName("QR-UOV/qruov5q31L3v324m114+Ed25519")
    QRUOV_5Q31L3V324M114_ED25519("QR-UOV/qruov5q31L3v324m114+Ed25519", QRUOV_5Q31L3V324M114, "Ed25519"),
    @SerializedName("QR-UOV/qruov5q31L3v324m114+Ed448")
    QRUOV_5Q31L3V324M114_ED448("QR-UOV/qruov5q31L3v324m114+Ed448", QRUOV_5Q31L3V324M114, "Ed448"),
    @SerializedName("QR-UOV/qruov5q31L10v1120m120+Ed25519")
    QRUOV_5Q31L10V1120M120_ED25519("QR-UOV/qruov5q31L10v1120m120+Ed25519", QRUOV_5Q31L10V1120M120, "Ed25519"),
    @SerializedName("QR-UOV/qruov5q31L10v1120m120+Ed448")
    QRUOV_5Q31L10V1120M120_ED448("QR-UOV/qruov5q31L10v1120m120+Ed448", QRUOV_5Q31L10V1120M120, "Ed448"),
    @SerializedName("QR-UOV/qruov5q7L10v1490m190+Ed25519")
    QRUOV_5Q7L10V1490M190_ED25519("QR-UOV/qruov5q7L10v1490m190+Ed25519", QRUOV_5Q7L10V1490M190, "Ed25519"),
    @SerializedName("QR-UOV/qruov5q7L10v1490m190+Ed448")
    QRUOV_5Q7L10V1490M190_ED448("QR-UOV/qruov5q7L10v1490m190+Ed448", QRUOV_5Q7L10V1490M190, "Ed448"),
    @SerializedName("AIMer-128f+Ed25519")
    AIMER_128F_ED25519("AIMer-128f+Ed25519", AIMER_128F, "Ed25519"),
    @SerializedName("AIMer-128f+Ed448")
    AIMER_128F_ED448("AIMer-128f+Ed448", AIMER_128F, "Ed448"),
    @SerializedName("AIMer-128s+Ed25519")
    AIMER_128S_ED25519("AIMer-128s+Ed25519", AIMER_128S, "Ed25519"),
    @SerializedName("AIMer-128s+Ed448")
    AIMER_128S_ED448("AIMer-128s+Ed448", AIMER_128S, "Ed448"),
    @SerializedName("AIMer-192f+Ed25519")
    AIMER_192F_ED25519("AIMer-192f+Ed25519", AIMER_192F, "Ed25519"),
    @SerializedName("AIMer-192f+Ed448")
    AIMER_192F_ED448("AIMer-192f+Ed448", AIMER_192F, "Ed448"),
    @SerializedName("AIMer-192s+Ed25519")
    AIMER_192S_ED25519("AIMer-192s+Ed25519", AIMER_192S, "Ed25519"),
    @SerializedName("AIMer-192s+Ed448")
    AIMER_192S_ED448("AIMer-192s+Ed448", AIMER_192S, "Ed448"),
    @SerializedName("AIMer-256f+Ed25519")
    AIMER_256F_ED25519("AIMer-256f+Ed25519", AIMER_256F, "Ed25519"),
    @SerializedName("AIMer-256f+Ed448")
    AIMER_256F_ED448("AIMer-256f+Ed448", AIMER_256F, "Ed448"),
    @SerializedName("AIMer-256s+Ed25519")
    AIMER_256S_ED25519("AIMer-256s+Ed25519", AIMER_256S, "Ed25519"),
    @SerializedName("AIMer-256s+Ed448")
    AIMER_256S_ED448("AIMer-256s+Ed448", AIMER_256S, "Ed448"),
    @SerializedName("FAEST-128S+Ed25519")
    FAEST_128S_ED25519("FAEST-128S+Ed25519", FAEST_128S, "Ed25519"),
    @SerializedName("FAEST-128S+Ed448")
    FAEST_128S_ED448("FAEST-128S+Ed448", FAEST_128S, "Ed448"),
    @SerializedName("FAEST-128F+Ed25519")
    FAEST_128F_ED25519("FAEST-128F+Ed25519", FAEST_128F, "Ed25519"),
    @SerializedName("FAEST-128F+Ed448")
    FAEST_128F_ED448("FAEST-128F+Ed448", FAEST_128F, "Ed448"),
    @SerializedName("FAEST-192S+Ed25519")
    FAEST_192S_ED25519("FAEST-192S+Ed25519", FAEST_192S, "Ed25519"),
    @SerializedName("FAEST-192S+Ed448")
    FAEST_192S_ED448("FAEST-192S+Ed448", FAEST_192S, "Ed448"),
    @SerializedName("FAEST-192F+Ed25519")
    FAEST_192F_ED25519("FAEST-192F+Ed25519", FAEST_192F, "Ed25519"),
    @SerializedName("FAEST-192F+Ed448")
    FAEST_192F_ED448("FAEST-192F+Ed448", FAEST_192F, "Ed448"),
    @SerializedName("FAEST-256S+Ed25519")
    FAEST_256S_ED25519("FAEST-256S+Ed25519", FAEST_256S, "Ed25519"),
    @SerializedName("FAEST-256S+Ed448")
    FAEST_256S_ED448("FAEST-256S+Ed448", FAEST_256S, "Ed448"),
    @SerializedName("FAEST-256F+Ed25519")
    FAEST_256F_ED25519("FAEST-256F+Ed25519", FAEST_256F, "Ed25519"),
    @SerializedName("FAEST-256F+Ed448")
    FAEST_256F_ED448("FAEST-256F+Ed448", FAEST_256F, "Ed448"),
    @SerializedName("FAEST-EM-128S+Ed25519")
    FAEST_EM_128S_ED25519("FAEST-EM-128S+Ed25519", FAEST_EM_128S, "Ed25519"),
    @SerializedName("FAEST-EM-128S+Ed448")
    FAEST_EM_128S_ED448("FAEST-EM-128S+Ed448", FAEST_EM_128S, "Ed448"),
    @SerializedName("FAEST-EM-128F+Ed25519")
    FAEST_EM_128F_ED25519("FAEST-EM-128F+Ed25519", FAEST_EM_128F, "Ed25519"),
    @SerializedName("FAEST-EM-128F+Ed448")
    FAEST_EM_128F_ED448("FAEST-EM-128F+Ed448", FAEST_EM_128F, "Ed448"),
    @SerializedName("FAEST-EM-192S+Ed25519")
    FAEST_EM_192S_ED25519("FAEST-EM-192S+Ed25519", FAEST_EM_192S, "Ed25519"),
    @SerializedName("FAEST-EM-192S+Ed448")
    FAEST_EM_192S_ED448("FAEST-EM-192S+Ed448", FAEST_EM_192S, "Ed448"),
    @SerializedName("FAEST-EM-192F+Ed25519")
    FAEST_EM_192F_ED25519("FAEST-EM-192F+Ed25519", FAEST_EM_192F, "Ed25519"),
    @SerializedName("FAEST-EM-192F+Ed448")
    FAEST_EM_192F_ED448("FAEST-EM-192F+Ed448", FAEST_EM_192F, "Ed448"),
    @SerializedName("FAEST-EM-256S+Ed25519")
    FAEST_EM_256S_ED25519("FAEST-EM-256S+Ed25519", FAEST_EM_256S, "Ed25519"),
    @SerializedName("FAEST-EM-256S+Ed448")
    FAEST_EM_256S_ED448("FAEST-EM-256S+Ed448", FAEST_EM_256S, "Ed448"),
    @SerializedName("FAEST-EM-256F+Ed25519")
    FAEST_EM_256F_ED25519("FAEST-EM-256F+Ed25519", FAEST_EM_256F, "Ed25519"),
    @SerializedName("FAEST-EM-256F+Ed448")
    FAEST_EM_256F_ED448("FAEST-EM-256F+Ed448", FAEST_EM_256F, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF2-FAST-R3+Ed25519")
    MQOM2_CAT1_GF2_FAST_R3_ED25519("MQOM2-CAT1-GF2-FAST-R3+Ed25519", MQOM2_CAT1_GF2_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF2-FAST-R3+Ed448")
    MQOM2_CAT1_GF2_FAST_R3_ED448("MQOM2-CAT1-GF2-FAST-R3+Ed448", MQOM2_CAT1_GF2_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF2-FAST-R5+Ed25519")
    MQOM2_CAT1_GF2_FAST_R5_ED25519("MQOM2-CAT1-GF2-FAST-R5+Ed25519", MQOM2_CAT1_GF2_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF2-FAST-R5+Ed448")
    MQOM2_CAT1_GF2_FAST_R5_ED448("MQOM2-CAT1-GF2-FAST-R5+Ed448", MQOM2_CAT1_GF2_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF2-SHORT-R3+Ed25519")
    MQOM2_CAT1_GF2_SHORT_R3_ED25519("MQOM2-CAT1-GF2-SHORT-R3+Ed25519", MQOM2_CAT1_GF2_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF2-SHORT-R3+Ed448")
    MQOM2_CAT1_GF2_SHORT_R3_ED448("MQOM2-CAT1-GF2-SHORT-R3+Ed448", MQOM2_CAT1_GF2_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF2-SHORT-R5+Ed25519")
    MQOM2_CAT1_GF2_SHORT_R5_ED25519("MQOM2-CAT1-GF2-SHORT-R5+Ed25519", MQOM2_CAT1_GF2_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF2-SHORT-R5+Ed448")
    MQOM2_CAT1_GF2_SHORT_R5_ED448("MQOM2-CAT1-GF2-SHORT-R5+Ed448", MQOM2_CAT1_GF2_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF16-FAST-R3+Ed25519")
    MQOM2_CAT1_GF16_FAST_R3_ED25519("MQOM2-CAT1-GF16-FAST-R3+Ed25519", MQOM2_CAT1_GF16_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF16-FAST-R3+Ed448")
    MQOM2_CAT1_GF16_FAST_R3_ED448("MQOM2-CAT1-GF16-FAST-R3+Ed448", MQOM2_CAT1_GF16_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF16-FAST-R5+Ed25519")
    MQOM2_CAT1_GF16_FAST_R5_ED25519("MQOM2-CAT1-GF16-FAST-R5+Ed25519", MQOM2_CAT1_GF16_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF16-FAST-R5+Ed448")
    MQOM2_CAT1_GF16_FAST_R5_ED448("MQOM2-CAT1-GF16-FAST-R5+Ed448", MQOM2_CAT1_GF16_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF16-SHORT-R3+Ed25519")
    MQOM2_CAT1_GF16_SHORT_R3_ED25519("MQOM2-CAT1-GF16-SHORT-R3+Ed25519", MQOM2_CAT1_GF16_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF16-SHORT-R3+Ed448")
    MQOM2_CAT1_GF16_SHORT_R3_ED448("MQOM2-CAT1-GF16-SHORT-R3+Ed448", MQOM2_CAT1_GF16_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF16-SHORT-R5+Ed25519")
    MQOM2_CAT1_GF16_SHORT_R5_ED25519("MQOM2-CAT1-GF16-SHORT-R5+Ed25519", MQOM2_CAT1_GF16_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF16-SHORT-R5+Ed448")
    MQOM2_CAT1_GF16_SHORT_R5_ED448("MQOM2-CAT1-GF16-SHORT-R5+Ed448", MQOM2_CAT1_GF16_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF256-FAST-R3+Ed25519")
    MQOM2_CAT1_GF256_FAST_R3_ED25519("MQOM2-CAT1-GF256-FAST-R3+Ed25519", MQOM2_CAT1_GF256_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF256-FAST-R3+Ed448")
    MQOM2_CAT1_GF256_FAST_R3_ED448("MQOM2-CAT1-GF256-FAST-R3+Ed448", MQOM2_CAT1_GF256_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF256-FAST-R5+Ed25519")
    MQOM2_CAT1_GF256_FAST_R5_ED25519("MQOM2-CAT1-GF256-FAST-R5+Ed25519", MQOM2_CAT1_GF256_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF256-FAST-R5+Ed448")
    MQOM2_CAT1_GF256_FAST_R5_ED448("MQOM2-CAT1-GF256-FAST-R5+Ed448", MQOM2_CAT1_GF256_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF256-SHORT-R3+Ed25519")
    MQOM2_CAT1_GF256_SHORT_R3_ED25519("MQOM2-CAT1-GF256-SHORT-R3+Ed25519", MQOM2_CAT1_GF256_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF256-SHORT-R3+Ed448")
    MQOM2_CAT1_GF256_SHORT_R3_ED448("MQOM2-CAT1-GF256-SHORT-R3+Ed448", MQOM2_CAT1_GF256_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT1-GF256-SHORT-R5+Ed25519")
    MQOM2_CAT1_GF256_SHORT_R5_ED25519("MQOM2-CAT1-GF256-SHORT-R5+Ed25519", MQOM2_CAT1_GF256_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT1-GF256-SHORT-R5+Ed448")
    MQOM2_CAT1_GF256_SHORT_R5_ED448("MQOM2-CAT1-GF256-SHORT-R5+Ed448", MQOM2_CAT1_GF256_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF2-FAST-R3+Ed25519")
    MQOM2_CAT3_GF2_FAST_R3_ED25519("MQOM2-CAT3-GF2-FAST-R3+Ed25519", MQOM2_CAT3_GF2_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF2-FAST-R3+Ed448")
    MQOM2_CAT3_GF2_FAST_R3_ED448("MQOM2-CAT3-GF2-FAST-R3+Ed448", MQOM2_CAT3_GF2_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF2-FAST-R5+Ed25519")
    MQOM2_CAT3_GF2_FAST_R5_ED25519("MQOM2-CAT3-GF2-FAST-R5+Ed25519", MQOM2_CAT3_GF2_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF2-FAST-R5+Ed448")
    MQOM2_CAT3_GF2_FAST_R5_ED448("MQOM2-CAT3-GF2-FAST-R5+Ed448", MQOM2_CAT3_GF2_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF2-SHORT-R3+Ed25519")
    MQOM2_CAT3_GF2_SHORT_R3_ED25519("MQOM2-CAT3-GF2-SHORT-R3+Ed25519", MQOM2_CAT3_GF2_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF2-SHORT-R3+Ed448")
    MQOM2_CAT3_GF2_SHORT_R3_ED448("MQOM2-CAT3-GF2-SHORT-R3+Ed448", MQOM2_CAT3_GF2_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF2-SHORT-R5+Ed25519")
    MQOM2_CAT3_GF2_SHORT_R5_ED25519("MQOM2-CAT3-GF2-SHORT-R5+Ed25519", MQOM2_CAT3_GF2_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF2-SHORT-R5+Ed448")
    MQOM2_CAT3_GF2_SHORT_R5_ED448("MQOM2-CAT3-GF2-SHORT-R5+Ed448", MQOM2_CAT3_GF2_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF16-FAST-R3+Ed25519")
    MQOM2_CAT3_GF16_FAST_R3_ED25519("MQOM2-CAT3-GF16-FAST-R3+Ed25519", MQOM2_CAT3_GF16_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF16-FAST-R3+Ed448")
    MQOM2_CAT3_GF16_FAST_R3_ED448("MQOM2-CAT3-GF16-FAST-R3+Ed448", MQOM2_CAT3_GF16_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF16-FAST-R5+Ed25519")
    MQOM2_CAT3_GF16_FAST_R5_ED25519("MQOM2-CAT3-GF16-FAST-R5+Ed25519", MQOM2_CAT3_GF16_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF16-FAST-R5+Ed448")
    MQOM2_CAT3_GF16_FAST_R5_ED448("MQOM2-CAT3-GF16-FAST-R5+Ed448", MQOM2_CAT3_GF16_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF16-SHORT-R3+Ed25519")
    MQOM2_CAT3_GF16_SHORT_R3_ED25519("MQOM2-CAT3-GF16-SHORT-R3+Ed25519", MQOM2_CAT3_GF16_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF16-SHORT-R3+Ed448")
    MQOM2_CAT3_GF16_SHORT_R3_ED448("MQOM2-CAT3-GF16-SHORT-R3+Ed448", MQOM2_CAT3_GF16_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF16-SHORT-R5+Ed25519")
    MQOM2_CAT3_GF16_SHORT_R5_ED25519("MQOM2-CAT3-GF16-SHORT-R5+Ed25519", MQOM2_CAT3_GF16_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF16-SHORT-R5+Ed448")
    MQOM2_CAT3_GF16_SHORT_R5_ED448("MQOM2-CAT3-GF16-SHORT-R5+Ed448", MQOM2_CAT3_GF16_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF256-FAST-R3+Ed25519")
    MQOM2_CAT3_GF256_FAST_R3_ED25519("MQOM2-CAT3-GF256-FAST-R3+Ed25519", MQOM2_CAT3_GF256_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF256-FAST-R3+Ed448")
    MQOM2_CAT3_GF256_FAST_R3_ED448("MQOM2-CAT3-GF256-FAST-R3+Ed448", MQOM2_CAT3_GF256_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF256-FAST-R5+Ed25519")
    MQOM2_CAT3_GF256_FAST_R5_ED25519("MQOM2-CAT3-GF256-FAST-R5+Ed25519", MQOM2_CAT3_GF256_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF256-FAST-R5+Ed448")
    MQOM2_CAT3_GF256_FAST_R5_ED448("MQOM2-CAT3-GF256-FAST-R5+Ed448", MQOM2_CAT3_GF256_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF256-SHORT-R3+Ed25519")
    MQOM2_CAT3_GF256_SHORT_R3_ED25519("MQOM2-CAT3-GF256-SHORT-R3+Ed25519", MQOM2_CAT3_GF256_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF256-SHORT-R3+Ed448")
    MQOM2_CAT3_GF256_SHORT_R3_ED448("MQOM2-CAT3-GF256-SHORT-R3+Ed448", MQOM2_CAT3_GF256_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT3-GF256-SHORT-R5+Ed25519")
    MQOM2_CAT3_GF256_SHORT_R5_ED25519("MQOM2-CAT3-GF256-SHORT-R5+Ed25519", MQOM2_CAT3_GF256_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT3-GF256-SHORT-R5+Ed448")
    MQOM2_CAT3_GF256_SHORT_R5_ED448("MQOM2-CAT3-GF256-SHORT-R5+Ed448", MQOM2_CAT3_GF256_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF2-FAST-R3+Ed25519")
    MQOM2_CAT5_GF2_FAST_R3_ED25519("MQOM2-CAT5-GF2-FAST-R3+Ed25519", MQOM2_CAT5_GF2_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF2-FAST-R3+Ed448")
    MQOM2_CAT5_GF2_FAST_R3_ED448("MQOM2-CAT5-GF2-FAST-R3+Ed448", MQOM2_CAT5_GF2_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF2-FAST-R5+Ed25519")
    MQOM2_CAT5_GF2_FAST_R5_ED25519("MQOM2-CAT5-GF2-FAST-R5+Ed25519", MQOM2_CAT5_GF2_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF2-FAST-R5+Ed448")
    MQOM2_CAT5_GF2_FAST_R5_ED448("MQOM2-CAT5-GF2-FAST-R5+Ed448", MQOM2_CAT5_GF2_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF2-SHORT-R3+Ed25519")
    MQOM2_CAT5_GF2_SHORT_R3_ED25519("MQOM2-CAT5-GF2-SHORT-R3+Ed25519", MQOM2_CAT5_GF2_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF2-SHORT-R3+Ed448")
    MQOM2_CAT5_GF2_SHORT_R3_ED448("MQOM2-CAT5-GF2-SHORT-R3+Ed448", MQOM2_CAT5_GF2_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF2-SHORT-R5+Ed25519")
    MQOM2_CAT5_GF2_SHORT_R5_ED25519("MQOM2-CAT5-GF2-SHORT-R5+Ed25519", MQOM2_CAT5_GF2_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF2-SHORT-R5+Ed448")
    MQOM2_CAT5_GF2_SHORT_R5_ED448("MQOM2-CAT5-GF2-SHORT-R5+Ed448", MQOM2_CAT5_GF2_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF16-FAST-R3+Ed25519")
    MQOM2_CAT5_GF16_FAST_R3_ED25519("MQOM2-CAT5-GF16-FAST-R3+Ed25519", MQOM2_CAT5_GF16_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF16-FAST-R3+Ed448")
    MQOM2_CAT5_GF16_FAST_R3_ED448("MQOM2-CAT5-GF16-FAST-R3+Ed448", MQOM2_CAT5_GF16_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF16-FAST-R5+Ed25519")
    MQOM2_CAT5_GF16_FAST_R5_ED25519("MQOM2-CAT5-GF16-FAST-R5+Ed25519", MQOM2_CAT5_GF16_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF16-FAST-R5+Ed448")
    MQOM2_CAT5_GF16_FAST_R5_ED448("MQOM2-CAT5-GF16-FAST-R5+Ed448", MQOM2_CAT5_GF16_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF16-SHORT-R3+Ed25519")
    MQOM2_CAT5_GF16_SHORT_R3_ED25519("MQOM2-CAT5-GF16-SHORT-R3+Ed25519", MQOM2_CAT5_GF16_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF16-SHORT-R3+Ed448")
    MQOM2_CAT5_GF16_SHORT_R3_ED448("MQOM2-CAT5-GF16-SHORT-R3+Ed448", MQOM2_CAT5_GF16_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF16-SHORT-R5+Ed25519")
    MQOM2_CAT5_GF16_SHORT_R5_ED25519("MQOM2-CAT5-GF16-SHORT-R5+Ed25519", MQOM2_CAT5_GF16_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF16-SHORT-R5+Ed448")
    MQOM2_CAT5_GF16_SHORT_R5_ED448("MQOM2-CAT5-GF16-SHORT-R5+Ed448", MQOM2_CAT5_GF16_SHORT_R5, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF256-FAST-R3+Ed25519")
    MQOM2_CAT5_GF256_FAST_R3_ED25519("MQOM2-CAT5-GF256-FAST-R3+Ed25519", MQOM2_CAT5_GF256_FAST_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF256-FAST-R3+Ed448")
    MQOM2_CAT5_GF256_FAST_R3_ED448("MQOM2-CAT5-GF256-FAST-R3+Ed448", MQOM2_CAT5_GF256_FAST_R3, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF256-FAST-R5+Ed25519")
    MQOM2_CAT5_GF256_FAST_R5_ED25519("MQOM2-CAT5-GF256-FAST-R5+Ed25519", MQOM2_CAT5_GF256_FAST_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF256-FAST-R5+Ed448")
    MQOM2_CAT5_GF256_FAST_R5_ED448("MQOM2-CAT5-GF256-FAST-R5+Ed448", MQOM2_CAT5_GF256_FAST_R5, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF256-SHORT-R3+Ed25519")
    MQOM2_CAT5_GF256_SHORT_R3_ED25519("MQOM2-CAT5-GF256-SHORT-R3+Ed25519", MQOM2_CAT5_GF256_SHORT_R3, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF256-SHORT-R3+Ed448")
    MQOM2_CAT5_GF256_SHORT_R3_ED448("MQOM2-CAT5-GF256-SHORT-R3+Ed448", MQOM2_CAT5_GF256_SHORT_R3, "Ed448"),
    @SerializedName("MQOM2-CAT5-GF256-SHORT-R5+Ed25519")
    MQOM2_CAT5_GF256_SHORT_R5_ED25519("MQOM2-CAT5-GF256-SHORT-R5+Ed25519", MQOM2_CAT5_GF256_SHORT_R5, "Ed25519"),
    @SerializedName("MQOM2-CAT5-GF256-SHORT-R5+Ed448")
    MQOM2_CAT5_GF256_SHORT_R5_ED448("MQOM2-CAT5-GF256-SHORT-R5+Ed448", MQOM2_CAT5_GF256_SHORT_R5, "Ed448"),
    @SerializedName("SDITH-HYPERCUBE-CAT1-GF256+Ed25519")
    SDITH_HYPERCUBE_CAT1_GF256_ED25519("SDITH-HYPERCUBE-CAT1-GF256+Ed25519", SDITH_HYPERCUBE_CAT1_GF256, "Ed25519"),
    @SerializedName("SDITH-HYPERCUBE-CAT1-GF256+Ed448")
    SDITH_HYPERCUBE_CAT1_GF256_ED448("SDITH-HYPERCUBE-CAT1-GF256+Ed448", SDITH_HYPERCUBE_CAT1_GF256, "Ed448"),
    @SerializedName("SDITH-HYPERCUBE-CAT3-GF256+Ed25519")
    SDITH_HYPERCUBE_CAT3_GF256_ED25519("SDITH-HYPERCUBE-CAT3-GF256+Ed25519", SDITH_HYPERCUBE_CAT3_GF256, "Ed25519"),
    @SerializedName("SDITH-HYPERCUBE-CAT3-GF256+Ed448")
    SDITH_HYPERCUBE_CAT3_GF256_ED448("SDITH-HYPERCUBE-CAT3-GF256+Ed448", SDITH_HYPERCUBE_CAT3_GF256, "Ed448"),
    @SerializedName("SDITH-HYPERCUBE-CAT5-GF256+Ed25519")
    SDITH_HYPERCUBE_CAT5_GF256_ED25519("SDITH-HYPERCUBE-CAT5-GF256+Ed25519", SDITH_HYPERCUBE_CAT5_GF256, "Ed25519"),
    @SerializedName("SDITH-HYPERCUBE-CAT5-GF256+Ed448")
    SDITH_HYPERCUBE_CAT5_GF256_ED448("SDITH-HYPERCUBE-CAT5-GF256+Ed448", SDITH_HYPERCUBE_CAT5_GF256, "Ed448"),
    @SerializedName("SDITH-HYPERCUBE-CAT1-P251+Ed25519")
    SDITH_HYPERCUBE_CAT1_P251_ED25519("SDITH-HYPERCUBE-CAT1-P251+Ed25519", SDITH_HYPERCUBE_CAT1_P251, "Ed25519"),
    @SerializedName("SDITH-HYPERCUBE-CAT1-P251+Ed448")
    SDITH_HYPERCUBE_CAT1_P251_ED448("SDITH-HYPERCUBE-CAT1-P251+Ed448", SDITH_HYPERCUBE_CAT1_P251, "Ed448"),
    @SerializedName("SDITH-HYPERCUBE-CAT3-P251+Ed25519")
    SDITH_HYPERCUBE_CAT3_P251_ED25519("SDITH-HYPERCUBE-CAT3-P251+Ed25519", SDITH_HYPERCUBE_CAT3_P251, "Ed25519"),
    @SerializedName("SDITH-HYPERCUBE-CAT3-P251+Ed448")
    SDITH_HYPERCUBE_CAT3_P251_ED448("SDITH-HYPERCUBE-CAT3-P251+Ed448", SDITH_HYPERCUBE_CAT3_P251, "Ed448"),
    @SerializedName("SDITH-HYPERCUBE-CAT5-P251+Ed25519")
    SDITH_HYPERCUBE_CAT5_P251_ED25519("SDITH-HYPERCUBE-CAT5-P251+Ed25519", SDITH_HYPERCUBE_CAT5_P251, "Ed25519"),
    @SerializedName("SDITH-HYPERCUBE-CAT5-P251+Ed448")
    SDITH_HYPERCUBE_CAT5_P251_ED448("SDITH-HYPERCUBE-CAT5-P251+Ed448", SDITH_HYPERCUBE_CAT5_P251, "Ed448"),
    @SerializedName("SDITH-THRESHOLD-CAT1-GF256+Ed25519")
    SDITH_THRESHOLD_CAT1_GF256_ED25519("SDITH-THRESHOLD-CAT1-GF256+Ed25519", SDITH_THRESHOLD_CAT1_GF256, "Ed25519"),
    @SerializedName("SDITH-THRESHOLD-CAT1-GF256+Ed448")
    SDITH_THRESHOLD_CAT1_GF256_ED448("SDITH-THRESHOLD-CAT1-GF256+Ed448", SDITH_THRESHOLD_CAT1_GF256, "Ed448"),
    @SerializedName("SDITH-THRESHOLD-CAT3-GF256+Ed25519")
    SDITH_THRESHOLD_CAT3_GF256_ED25519("SDITH-THRESHOLD-CAT3-GF256+Ed25519", SDITH_THRESHOLD_CAT3_GF256, "Ed25519"),
    @SerializedName("SDITH-THRESHOLD-CAT3-GF256+Ed448")
    SDITH_THRESHOLD_CAT3_GF256_ED448("SDITH-THRESHOLD-CAT3-GF256+Ed448", SDITH_THRESHOLD_CAT3_GF256, "Ed448"),
    @SerializedName("SDITH-THRESHOLD-CAT5-GF256+Ed25519")
    SDITH_THRESHOLD_CAT5_GF256_ED25519("SDITH-THRESHOLD-CAT5-GF256+Ed25519", SDITH_THRESHOLD_CAT5_GF256, "Ed25519"),
    @SerializedName("SDITH-THRESHOLD-CAT5-GF256+Ed448")
    SDITH_THRESHOLD_CAT5_GF256_ED448("SDITH-THRESHOLD-CAT5-GF256+Ed448", SDITH_THRESHOLD_CAT5_GF256, "Ed448"),
    @SerializedName("SDITH-THRESHOLD-CAT1-P251+Ed25519")
    SDITH_THRESHOLD_CAT1_P251_ED25519("SDITH-THRESHOLD-CAT1-P251+Ed25519", SDITH_THRESHOLD_CAT1_P251, "Ed25519"),
    @SerializedName("SDITH-THRESHOLD-CAT1-P251+Ed448")
    SDITH_THRESHOLD_CAT1_P251_ED448("SDITH-THRESHOLD-CAT1-P251+Ed448", SDITH_THRESHOLD_CAT1_P251, "Ed448"),
    @SerializedName("SDITH-THRESHOLD-CAT3-P251+Ed25519")
    SDITH_THRESHOLD_CAT3_P251_ED25519("SDITH-THRESHOLD-CAT3-P251+Ed25519", SDITH_THRESHOLD_CAT3_P251, "Ed25519"),
    @SerializedName("SDITH-THRESHOLD-CAT3-P251+Ed448")
    SDITH_THRESHOLD_CAT3_P251_ED448("SDITH-THRESHOLD-CAT3-P251+Ed448", SDITH_THRESHOLD_CAT3_P251, "Ed448"),
    @SerializedName("SDITH-THRESHOLD-CAT5-P251+Ed25519")
    SDITH_THRESHOLD_CAT5_P251_ED25519("SDITH-THRESHOLD-CAT5-P251+Ed25519", SDITH_THRESHOLD_CAT5_P251, "Ed25519"),
    @SerializedName("SDITH-THRESHOLD-CAT5-P251+Ed448")
    SDITH_THRESHOLD_CAT5_P251_ED448("SDITH-THRESHOLD-CAT5-P251+Ed448", SDITH_THRESHOLD_CAT5_P251, "Ed448");

    private final String identifier;
    private final String jcaName;
    private final String provider;
    private final AlgorithmParameterSpec parameterSpec;
    private final SignatureAlgorithm postQuantumComponent;
    private final String classicalAlgorithm;

    SignatureAlgorithm(String identifier, String jcaName, String provider, AlgorithmParameterSpec parameterSpec) {
        this.identifier = identifier;
        this.jcaName = jcaName;
        this.provider = provider;
        this.parameterSpec = parameterSpec;
        this.postQuantumComponent = null;
        this.classicalAlgorithm = null;
    }

    SignatureAlgorithm(String identifier, SignatureAlgorithm postQuantumComponent, String classicalAlgorithm) {
        this.identifier = identifier;
        this.jcaName = postQuantumComponent.jcaName;
        this.provider = postQuantumComponent.provider;
        this.parameterSpec = postQuantumComponent.parameterSpec;
        this.postQuantumComponent = postQuantumComponent;
        this.classicalAlgorithm = classicalAlgorithm;
    }

    public boolean hybrid() {
        return nativeHybrid() || customHybrid();
    }

    public boolean nativeHybrid() {
        return parameterSpec == null && postQuantumComponent == null;
    }

    public boolean customHybrid() {
        return postQuantumComponent != null;
    }

    public SignatureAlgorithm postQuantumComponent() {
        return customHybrid() ? postQuantumComponent : this;
    }

    public String classicalAlgorithm() {
        return classicalAlgorithm;
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
