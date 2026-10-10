package dev.krypt04mcg.util;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.time.Instant;

final class InstantTypeAdapter extends TypeAdapter<Instant> {
    /**
     * Writes the supplied value to the output used by the JSON timestamp conversion.
     *
     * @param out the out supplied to this operation
     * @param value the value supplied to this operation
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    @Override
    public void write(JsonWriter out, Instant value) throws IOException {
        if (value == null) {
            out.nullValue();
            return;
        }
        out.value(value.toString());
    }

    /**
     * Reads the next value from the input used by the JSON timestamp conversion.
     *
     * @param in the in supplied to this operation
     * @return the result described above
     * @throws IOException if input/output, stored-state validation or resource handling fails
     */
    @Override
    public Instant read(JsonReader in) throws IOException {
        if (in.peek() == JsonToken.NULL) {
            in.nextNull();
            return null;
        }
        return Instant.parse(in.nextString());
    }
}
