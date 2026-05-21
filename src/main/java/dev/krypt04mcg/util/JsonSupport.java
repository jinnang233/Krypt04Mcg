package dev.krypt04mcg.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.time.Instant;

public final class JsonSupport {
    private JsonSupport() {
    }

    public static Gson prettyGson() {
        return new GsonBuilder()
                .registerTypeAdapter(Instant.class, new InstantTypeAdapter())
                .setPrettyPrinting()
                .create();
    }
}
