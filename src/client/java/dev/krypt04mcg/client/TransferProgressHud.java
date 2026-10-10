package dev.krypt04mcg.client;

import dev.krypt04mcg.chat.TransferProgressTracker;
import dev.krypt04mcg.config.Krypt04McgConfig;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.resources.language.I18n;

import java.util.ArrayList;

/** Loader-independent drawing; platform entry points register the HUD layer. */
public final class TransferProgressHud {
    private final TransferProgressTracker tracker;
    private final Krypt04McgConfig config;

    /**
     * Creates a transfer progress hud with the supplied dependencies and initial state.
     *
     * @param tracker the tracker supplied to this operation
     * @param config the config supplied to this operation
     */
    public TransferProgressHud(TransferProgressTracker tracker, Krypt04McgConfig config) {
        this.tracker = tracker;
        this.config = config;
    }

    /**
     * Draws the current view from the available client state.
     *
     * @param graphics the graphics supplied to this operation
     */
    public void render(GuiGraphicsExtractor graphics) {
        Minecraft client = Minecraft.getInstance();
        if (client.player == null || client.gui.hud.isHidden()) return;
        int width = Math.min(220, graphics.guiWidth() - 16);
        int availableRows = Math.min(4, (graphics.guiHeight() - 64) / 36);
        if (width < 100 || availableRows <= 0) return;
        var sending = config.showProgress ? tracker.snapshot(TransferProgressTracker.Direction.SEND) : java.util.List.<TransferProgressTracker.Update>of();
        var receiving = config.showReceiveProgress ? tracker.snapshot(TransferProgressTracker.Direction.RECEIVE) : java.util.List.<TransferProgressTracker.Update>of();
        var rows = new ArrayList<TransferProgressTracker.Update>();
        // Reserve a row for each direction, even when the send queue is busy.
        for (int i = 0; i < 2; i++) {
            if (i < sending.size() && rows.size() < availableRows) rows.add(sending.get(i));
            if (i < receiving.size() && rows.size() < availableRows) rows.add(receiving.get(i));
        }
        int x = graphics.guiWidth() - width - 8;
        int y = 56;
        for (var row : rows) {
            int color = switch (row.status()) {
                case FAILED, TIMED_OUT -> 0xFFF07B79;
                case CANCELLED -> 0xFF99A3AE;
                default -> row.direction() == TransferProgressTracker.Direction.SEND ? 0xFF49B5FF : 0xFF66D6A0;
            };
            graphics.fill(x, y, x + width, y + 34, 0xDD101820);
            graphics.fill(x + 6, y + 27, x + width - 6, y + 31, 0xFF344150);
            int filled = (int) ((long) (width - 12) * row.completed() / row.total());
            if (filled > 0) graphics.fill(x + 6, y + 27, x + 6 + filled, y + 31, color);
            graphics.nextStratum();
            String direction = row.direction() == TransferProgressTracker.Direction.SEND ? "send" : "receive";
            String title = I18n.get("text.krypt04mcg.progress." + direction, row.peer());
            graphics.text(client.font, client.font.plainSubstrByWidth(title, width - 12), x + 6, y + 4, 0xFFFFFFFF, false);
            String counts = row.percent() + "% (" + row.completed() + "/" + row.total() + ")";
            graphics.text(client.font, counts, x + 6, y + 15, 0xFFCAD5DF, false);
            String statusKey = row.status() == TransferProgressTracker.Status.COMPLETE
                    ? direction + "_complete" : row.status().name().toLowerCase(java.util.Locale.ROOT);
            String status = client.font.plainSubstrByWidth(I18n.get("text.krypt04mcg.progress." + statusKey),
                    Math.max(0, width - client.font.width(counts) - 24));
            graphics.text(client.font, status, x + width - 6 - client.font.width(status), y + 15, color, false);
            y += 36;
        }
    }
}
