package dev.obscuralink.model;

public enum PacketType {
    KEM_MESSAGE(1),
    SIGNED_KEM_MESSAGE(2),
    SESSION_EXCHANGE(3),
    SESSION_MESSAGE(4);

    private final int id;

    PacketType(int id) {
        this.id = id;
    }

    public int id() {
        return id;
    }

    public static PacketType fromId(int id) {
        for (PacketType type : values()) {
            if (type.id == id) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown packet type: " + id);
    }
}
