package dev.obscuralink.model;

public record PublicIdentity(
        String owner,
        String uuid,
        KeyRecord kemPublicKey,
        KeyRecord signaturePublicKey
) {
}
