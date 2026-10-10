package dev.krypt04mcg.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.time.Instant;

public final class JsonSupport {
    /**
     * Prevents direct instantiation of this stateless utility.
     */
    private JsonSupport() {
    }

    /**
     * Performs the pretty gson operation for the shared JSON serialization.
     *
     * @return the result described above
     */
    public static Gson prettyGson() {
        return new GsonBuilder()
                .registerTypeAdapter(Instant.class, new InstantTypeAdapter())
                .setPrettyPrinting()
                .create();
    }
}
