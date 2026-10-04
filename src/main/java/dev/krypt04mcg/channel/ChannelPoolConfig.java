package dev.krypt04mcg.channel;

import dev.krypt04mcg.protocol.RawChannelPayload;
import dev.krypt04mcg.util.JsonSupport;
import java.io.IOException;
import java.nio.file.*;

/** Client channel pool count without Cloth Config; restart required. */
public final class ChannelPoolConfig {
    public int apiChannelCount = 16;
    public static int load(Path configDirectory) {
        Path file = configDirectory.resolve("krypt04mcg-stream.json");
        try {
            if (!Files.exists(file)) return 16;
            if (Files.size(file) > 4096) throw new IOException("Channel config too large");
            var config = JsonSupport.prettyGson().fromJson(Files.readString(file), ChannelPoolConfig.class);
            if (config == null) throw new IOException("Empty channel config");
            return RawChannelPayload.channelCount(config.apiChannelCount);
        } catch (IOException | RuntimeException e) {
            org.slf4j.LoggerFactory.getLogger(ChannelPoolConfig.class).warn("Unable to load channel pool config {}; using 16 channels", file, e);
            return 16;
        }
    }
}
