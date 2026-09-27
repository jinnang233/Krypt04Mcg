package dev.krypt04mcg.config;

public class Krypt04McgConfig {
    public boolean enableDataApi = false;
    public String apiReceiver = "";
    public boolean enableFileSending = false;
    public boolean enableFileReceiving = false;
    public boolean permanentlyDisableFileSharing = false;
    public boolean showProgress = true;
    public boolean hideEncryptedRawMessage = true;
    public boolean verboseMessages = false;
    public boolean enableCompression = true;
    public boolean showReceiveProgress = true;
    public boolean enableConversationHistory = false;
    public boolean showDisclaimerWarning = true;

    public int fragmentSize = 180;

    public int sendDelayMs = 250;

    public int sessionTtlMinutes = 60;

    public int maxPacketAgeSeconds = 300;

    public int maxFutureSkewSeconds = 60;

    public int maxMessagesPerSession = 100;

    public long rotateAfterBytes = 1024L * 1024L;

    public int reassemblyTimeoutSeconds = 120;
    public int maxReassemblyMessages = 128;
    public int maxFragmentsPerMessage = 512;
    public int maxConversationMessages = 300;
    public int maxCachedSentMessages = 12;
    public int maxDataTransfers = 16;
    public int maxDataReceipts = 32;
    public int maxDataAttempts = 3;
    public int maxDataQueuedMiB = 16;
    public int dataAckTimeoutSeconds = 65;
    public int dataTransferTimeoutSeconds = 240;
    public int dataFragmentsPerTick = 4;
    public int sharingOfferTimeoutSeconds = 60;
    public int maxPendingSharingOffers = 4;

    public int reassemblyTimeoutSeconds() {
        return Math.clamp(reassemblyTimeoutSeconds, 1, 3600);
    }

    public int maxReassemblyMessages() {
        return Math.clamp(maxReassemblyMessages, 1, 1024);
    }

    public int maxFragmentsPerMessage() {
        return Math.clamp(maxFragmentsPerMessage, 1, 4096);
    }

    public int maxConversationMessages() {
        return Math.clamp(maxConversationMessages, 1, 10000);
    }

    public int maxCachedSentMessages() {
        return Math.clamp(maxCachedSentMessages, 1, 256);
    }

    public int maxDataTransfers() {
        return Math.clamp(maxDataTransfers, 1, 128);
    }

    public int maxDataReceipts() {
        return Math.clamp(maxDataReceipts, 1, 256);
    }

    public int maxDataAttempts() {
        return Math.clamp(maxDataAttempts, 1, 10);
    }

    public int maxDataQueuedMiB() {
        return Math.clamp(maxDataQueuedMiB, 1, 256);
    }

    public int dataAckTimeoutSeconds() {
        return Math.clamp(dataAckTimeoutSeconds, 61, 240);
    }

    public int dataTransferTimeoutSeconds() {
        return Math.clamp(dataTransferTimeoutSeconds, 1, 300);
    }

    public int dataFragmentsPerTick() {
        return Math.clamp(dataFragmentsPerTick, 1, 64);
    }

    public int sharingOfferTimeoutSeconds() {
        return Math.clamp(sharingOfferTimeoutSeconds, 1, 300);
    }

    public int maxPendingSharingOffers() {
        return Math.clamp(maxPendingSharingOffers, 1, 32);
    }

    public ChatSendMode chatSendMode = ChatSendMode.CHAT;
    public String serverCommandTemplate = "/msg <receiver> <fragment>";
    public String messagePrefix = "[Krypt04Mcg]";
    public String packetPrefix = "[KRYPT04MCG]";
    public boolean receiveRegexMode = false;
    public String receiveRegex = "^\\[KRYPT04MCG\\] .+";
    public boolean shadowListenMode = false;
    public java.util.List<String> shadowListenRegexes = new java.util.ArrayList<>(
            java.util.List.of("^<(?<player>[^>]+)>\\s*(?<message>.*)$"));
    public String shadowListenRegex = "^<(?<player>[^>]+)>\\s*(?<message>.*)$";
    public KemAlgorithm kemAlgorithm = KemAlgorithm.CMCE_MCELIECE348864;
    public KemAlgorithm ephemeralKemAlgorithm = KemAlgorithm.ML_KEM_768;
    public SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.FALCON_512;
    public AeadAlgorithm aeadAlgorithm = AeadAlgorithm.AES_256_GCM;
}
