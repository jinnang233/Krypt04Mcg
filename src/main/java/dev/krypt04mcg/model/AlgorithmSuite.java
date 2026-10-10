package dev.krypt04mcg.model;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;

public record AlgorithmSuite(String kem, String signature, String aead, String hkdf) {
    public static final String HKDF_SHA256 = "HKDF-SHA256";

    /**
     * Performs the defaults operation for the algorithm suite.
     *
     * @return the result described above
     */
    public static AlgorithmSuite defaults() {
        return of(KemAlgorithm.ML_KEM_768_X25519, SignatureAlgorithm.MLDSA65_ED25519_SHA512,
                AeadAlgorithm.AES_256_GCM);
    }

    /**
     * Resolves the supplied values into the definition used by the algorithm suite.
     *
     * @param kem the kem supplied to this operation
     * @param signature the signature bytes or signature representation to verify
     * @param aead the aead supplied to this operation
     * @return the result described above
     */
    public static AlgorithmSuite of(KemAlgorithm kem, SignatureAlgorithm signature, AeadAlgorithm aead) {
        return new AlgorithmSuite(kem.identifier(), signature.identifier(), aead.identifier(), HKDF_SHA256);
    }
}
