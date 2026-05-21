package dev.obscuralink.model;

public record LocalKeyMaterial(
        KeyRecord kemPublicKey,
        KeyRecord kemPrivateKey,
        KeyRecord signaturePublicKey,
        KeyRecord signaturePrivateKey
) {
}
