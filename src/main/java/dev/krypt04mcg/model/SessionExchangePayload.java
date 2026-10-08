package dev.krypt04mcg.model;

public record SessionExchangePayload(
        int version,
        Kind kind,
        String initiator,
        String initiatorUuid,
        String responder,
        String responderUuid,
        String sessionId,
        String requestMessageId,
        String initiatorFingerprint,
        String responderFingerprint,
        String ephemeralKem,
        String ephemeralPublicKey,
        String sessionSecret,
        long createdAtMillis,
        String previousSessionId,
        long requestEpoch
) {
    // v1 cannot distinguish an unseen delayed request from a new negotiation.
    public static final int VERSION = 2;

    public enum Kind {
        REQUEST,
        RESPONSE
    }
}
