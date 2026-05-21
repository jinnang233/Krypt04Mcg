package dev.obscuralink.config;

import me.shedaniel.autoconfig.ConfigData;
import me.shedaniel.autoconfig.annotation.Config;
import me.shedaniel.autoconfig.annotation.ConfigEntry;

@Config(name = "obscuralink")
public final class ObscuraLinkConfig implements ConfigData {
    public boolean showProgress = true;
    public boolean hideEncryptedRawMessage = true;
    public boolean verboseMessages = false;
    public boolean enableCompression = true;
    public boolean showReceiveProgress = true;

    @ConfigEntry.BoundedDiscrete(min = 64, max = 200)
    public int fragmentSize = 180;

    @ConfigEntry.BoundedDiscrete(min = 0, max = 5000)
    public int sendDelayMs = 250;

    @ConfigEntry.BoundedDiscrete(min = 5, max = 1440)
    public int sessionTtlMinutes = 60;

    @ConfigEntry.BoundedDiscrete(min = 1, max = 10000)
    public int maxMessagesPerSession = 100;

    public long rotateAfterBytes = 1024L * 1024L;

    public boolean receiveRegexMode = false;
    public String receiveRegex = "^\\[OBSCURA\\] .+";
    public boolean shadowListenMode = false;
    public String shadowListenRegex = "^<(?<player>[^>]+)>\\s*(?<message>.*)$";
    public String kemAlgorithm = "CMCE/mceliece348864";
    public String signatureAlgorithm = "Falcon-512";
    public String aeadAlgorithm = "AES-256-GCM";
}
