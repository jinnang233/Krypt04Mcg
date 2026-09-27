package dev.krypt04mcg.config;

import me.shedaniel.autoconfig.ConfigData;
import me.shedaniel.autoconfig.annotation.Config;
import me.shedaniel.autoconfig.annotation.ConfigEntry;

@Config(name = "krypt04mcg")
public final class ClothKrypt04McgConfig implements ConfigData {
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

    @ConfigEntry.BoundedDiscrete(min = 64, max = 200)
    public int fragmentSize = 180;

    @ConfigEntry.BoundedDiscrete(min = 0, max = 5000)
    public int sendDelayMs = 250;

    @ConfigEntry.BoundedDiscrete(min = 5, max = 1440)
    public int sessionTtlMinutes = 60;

    @ConfigEntry.BoundedDiscrete(min = 30, max = 3600)
    public int maxPacketAgeSeconds = 300;

    @ConfigEntry.BoundedDiscrete(min = 0, max = 300)
    public int maxFutureSkewSeconds = 60;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 10000)
    public int maxMessagesPerSession = 100;

    public long rotateAfterBytes = 1024L * 1024L;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 86400)
    public int reassemblyTimeoutSeconds = 120;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 16384)
    public int maxReassemblyMessages = 128;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 65536)
    public int maxFragmentsPerMessage = 512;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 100000)
    public int maxConversationMessages = 300;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 4096)
    public int maxCachedSentMessages = 12;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 4096)
    public int maxDataTransfers = 16;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 8192)
    public int maxDataReceipts = 32;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 100)
    public int maxDataAttempts = 3;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 4096)
    public int maxDataQueuedMiB = 16;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 1024)
    public int socketMaxBufferedMiB = 4;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 1024)
    public int socketWindowChunks = 4;

    @ConfigEntry.BoundedDiscrete(min = 61, max = 299)
    public int dataAckTimeoutSeconds = 65;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 86400)
    public int dataTransferTimeoutSeconds = 240;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 1024)
    public int dataFragmentsPerTick = 8;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 300)
    public int sharingOfferTimeoutSeconds = 60;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 1024)
    public int maxPendingSharingOffers = 4;

    public ChatSendMode chatSendMode = ChatSendMode.CHAT;
    public String serverCommandTemplate = "/msg <receiver> <fragment>";
    public String messagePrefix = "[Krypt04Mcg]";
    public String packetPrefix = "[KRYPT04MCG]";
    public boolean receiveRegexMode = false;
    public String receiveRegex = "^\\[KRYPT04MCG\\] .+";
    public boolean shadowListenMode = false;
    public java.util.List<String> shadowListenRegexes = new java.util.ArrayList<>(
            java.util.List.of("^<(?<player>[^>]+)>\\s*(?<message>.*)$"));
    @ConfigEntry.Gui.Excluded
    public String shadowListenRegex = "^<(?<player>[^>]+)>\\s*(?<message>.*)$";
    public KemAlgorithm kemAlgorithm = KemAlgorithm.CMCE_MCELIECE348864;
    public KemAlgorithm ephemeralKemAlgorithm = KemAlgorithm.ML_KEM_768;
    public SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.FALCON_512;
    public AeadAlgorithm aeadAlgorithm = AeadAlgorithm.AES_256_GCM;

    Krypt04McgConfig toCoreConfig() {
        Krypt04McgConfig config = new Krypt04McgConfig();
        copyTo(config);
        return config;
    }

    void copyTo(Krypt04McgConfig config) {
        config.enableDataApi = enableDataApi;
        config.apiReceiver = apiReceiver;
        config.enableFileSending = enableFileSending;
        config.enableFileReceiving = enableFileReceiving;
        config.permanentlyDisableFileSharing = permanentlyDisableFileSharing;
        config.showProgress = showProgress;
        config.hideEncryptedRawMessage = hideEncryptedRawMessage;
        config.verboseMessages = verboseMessages;
        config.enableCompression = enableCompression;
        config.showReceiveProgress = showReceiveProgress;
        config.enableConversationHistory = enableConversationHistory;
        config.showDisclaimerWarning = showDisclaimerWarning;
        config.fragmentSize = fragmentSize;
        config.sendDelayMs = sendDelayMs;
        config.sessionTtlMinutes = sessionTtlMinutes;
        config.maxPacketAgeSeconds = maxPacketAgeSeconds;
        config.maxFutureSkewSeconds = maxFutureSkewSeconds;
        config.maxMessagesPerSession = maxMessagesPerSession;
        config.rotateAfterBytes = rotateAfterBytes;
        config.reassemblyTimeoutSeconds = reassemblyTimeoutSeconds;
        config.maxReassemblyMessages = maxReassemblyMessages;
        config.maxFragmentsPerMessage = maxFragmentsPerMessage;
        config.maxConversationMessages = maxConversationMessages;
        config.maxCachedSentMessages = maxCachedSentMessages;
        config.maxDataTransfers = maxDataTransfers;
        config.maxDataReceipts = maxDataReceipts;
        config.maxDataAttempts = maxDataAttempts;
        config.maxDataQueuedMiB = maxDataQueuedMiB;
        config.socketMaxBufferedMiB = socketMaxBufferedMiB;
        config.socketWindowChunks = socketWindowChunks;
        config.dataAckTimeoutSeconds = dataAckTimeoutSeconds;
        config.dataTransferTimeoutSeconds = dataTransferTimeoutSeconds;
        config.dataFragmentsPerTick = dataFragmentsPerTick;
        config.sharingOfferTimeoutSeconds = sharingOfferTimeoutSeconds;
        config.maxPendingSharingOffers = maxPendingSharingOffers;
        config.chatSendMode = chatSendMode;
        config.serverCommandTemplate = serverCommandTemplate;
        config.messagePrefix = messagePrefix;
        config.packetPrefix = packetPrefix;
        config.receiveRegexMode = receiveRegexMode;
        config.receiveRegex = receiveRegex;
        config.shadowListenMode = shadowListenMode;
        config.shadowListenRegexes = new java.util.ArrayList<>(
                shadowListenRegexes == null ? java.util.List.of(shadowListenRegex) : shadowListenRegexes);
        config.shadowListenRegex = shadowListenRegex;
        config.kemAlgorithm = kemAlgorithm == null ? KemAlgorithm.CMCE_MCELIECE348864 : kemAlgorithm;
        config.ephemeralKemAlgorithm = ephemeralKemAlgorithm == null ? KemAlgorithm.ML_KEM_768 : ephemeralKemAlgorithm;
        config.signatureAlgorithm = signatureAlgorithm == null ? SignatureAlgorithm.FALCON_512 : signatureAlgorithm;
        config.aeadAlgorithm = aeadAlgorithm == null ? AeadAlgorithm.AES_256_GCM : aeadAlgorithm;
    }
}
