package dev.krypt04mcg.protocol;

import java.io.*;
import java.nio.file.*;

/** Application file content inside an encrypted stream; no transport envelopes or fragmentation. */
public final class FileStreamCodec {
    public static final int MAX_FILE_BYTES = 10 * 1024 * 1024;
    public record FileData(String name, byte[] data) {}
    private FileStreamCodec() {}
    public static byte[] encode(Path path) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException("Not a regular file");
        byte[] contents;
        try (var in = Files.newInputStream(path)) { contents = in.readNBytes(MAX_FILE_BYTES + 1); }
        if (contents.length > MAX_FILE_BYTES) throw new IOException("File exceeds 10 MiB");
        String name = path.getFileName().toString();
        if (name.length() > 180) name = name.substring(name.length() - 180);
        var buffer = new ByteArrayOutputStream();
        var out = new DataOutputStream(buffer);
        out.writeUTF(name); out.writeInt(contents.length); out.write(contents);
        return buffer.toByteArray();
    }
    public static FileData read(InputStream input) throws IOException {
        var in = new DataInputStream(input);
        int nameBytes = in.readUnsignedShort();
        if (nameBytes == 0 || nameBytes > 540) throw new IOException("Invalid file name");
        byte[] name = in.readNBytes(nameBytes);
        if (name.length != nameBytes) throw new EOFException();
        var utf = new ByteArrayOutputStream(); var prefix = new DataOutputStream(utf);
        prefix.writeShort(nameBytes); prefix.write(name);
        String filename = new DataInputStream(new ByteArrayInputStream(utf.toByteArray())).readUTF();
        if (filename.length() > 180) throw new IOException("Invalid file name");
        int size = in.readInt();
        if (size < 0 || size > MAX_FILE_BYTES) throw new IOException("File exceeds 10 MiB");
        byte[] bytes = in.readNBytes(size);
        if (bytes.length != size || in.read() != -1) throw new IOException("Incomplete file or trailing bytes");
        return new FileData(filename, bytes);
    }
}
