package dev.krypt04mcg.protocol;

import java.io.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class FileStreamCodecTest {
    @TempDir Path root;
    @Test void roundTripsBinaryContentAndRejectsTruncationAndTrailingData() throws Exception {
        Path file = root.resolve("文件.bin"); byte[] bytes = {0, -1, 42}; Files.write(file, bytes);
        byte[] encoded = FileStreamCodec.encode(file);
        var result = FileStreamCodec.read(new ByteArrayInputStream(encoded));
        assertEquals("文件.bin", result.name()); assertArrayEquals(bytes, result.data());
        assertThrows(IOException.class, () -> FileStreamCodec.read(new ByteArrayInputStream(java.util.Arrays.copyOf(encoded, encoded.length - 1))));
        assertThrows(IOException.class, () -> FileStreamCodec.read(new ByteArrayInputStream(java.util.Arrays.copyOf(encoded, encoded.length + 1))));
    }
    @Test void rejectsOversizeFileAndAnnouncedLengthBeforeAllocation() throws Exception {
        Path file = root.resolve("large.bin");
        try (var out = new RandomAccessFile(file.toFile(), "rw")) { out.setLength(FileStreamCodec.MAX_FILE_BYTES + 1L); }
        assertThrows(IOException.class, () -> FileStreamCodec.encode(file));
        var bytes = new ByteArrayOutputStream(); var out = new DataOutputStream(bytes);
        out.writeUTF("evil.bin"); out.writeInt(Integer.MAX_VALUE);
        assertThrows(IOException.class, () -> FileStreamCodec.read(new ByteArrayInputStream(bytes.toByteArray())));
    }
}
