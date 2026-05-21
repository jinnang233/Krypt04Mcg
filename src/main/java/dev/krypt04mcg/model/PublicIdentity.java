package dev.krypt04mcg.model;

public record PublicIdentity(
        String owner,
        String uuid,
        KeyRecord kemPublicKey,
        KeyRecord signaturePublicKey
) {
}
