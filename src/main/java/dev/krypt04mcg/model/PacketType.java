package dev.krypt04mcg.model;

public enum PacketType {
    KEM_MESSAGE(1),
    SIGNED_KEM_MESSAGE(2),
    SESSION_EXCHANGE(3),
    SESSION_MESSAGE(4);

    private final int id;

    /**
     * Creates a packet type with the supplied dependencies and initial state.
     *
     * @param id the id supplied to this operation
     */
    PacketType(int id) {
        this.id = id;
    }

    /**
     * Returns the id value used by the packet type.
     *
     * @return the result described above
     */
    public int id() {
        return id;
    }

    /**
     * Returns the recorded type for the packet type.
     *
     * @param id the id supplied to this operation
     * @return the result described above
     */
    public static PacketType fromId(int id) {
        for (PacketType type : values()) {
            if (type.id == id) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown packet type: " + id);
    }
}
