package dev.krypt04mcg.model;

public record SessionMessagePayload(int version, String message) {
    public static final int VERSION = 2;
}
