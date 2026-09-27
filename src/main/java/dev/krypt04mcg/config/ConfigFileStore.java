package dev.krypt04mcg.config;

import com.google.gson.JsonParseException;
import dev.krypt04mcg.util.JsonSupport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Uses the same JSON file as Cloth AutoConfig, including when Cloth is absent. */
public final class ConfigFileStore {
    private ConfigFileStore() {}

    public static Krypt04McgConfig load(Path file) throws IOException {
        var gson = JsonSupport.prettyGson();
        if (!Files.exists(file)) {
            var defaults = new Krypt04McgConfig();
            Files.createDirectories(file.toAbsolutePath().getParent());
            Files.writeString(file, gson.toJson(defaults), StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE_NEW);
            return defaults;
        }
        try {
            var config = gson.fromJson(Files.readString(file, StandardCharsets.UTF_8), Krypt04McgConfig.class);
            if (config == null) throw new IOException("Configuration must be a JSON object: " + file);
            return config;
        } catch (JsonParseException e) {
            throw new IOException("Invalid configuration JSON: " + file, e);
        }
    }
}
