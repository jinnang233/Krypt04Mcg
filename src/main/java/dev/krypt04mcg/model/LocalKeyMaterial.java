package dev.krypt04mcg.model;

public record LocalKeyMaterial(
        KeyRecord kemPublicKey,
        KeyRecord kemPrivateKey,
        KeyRecord signaturePublicKey,
        KeyRecord signaturePrivateKey
) {
}
