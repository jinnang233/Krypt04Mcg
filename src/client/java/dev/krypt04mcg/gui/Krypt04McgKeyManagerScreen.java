package dev.krypt04mcg.gui;

import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SessionService;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.Tooltip;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.util.FormattedCharSequence;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Public-key management using the same storage and trust rules as /k04m key. */
public final class Krypt04McgKeyManagerScreen extends Screen {
    private static final String PREFIX = "text.krypt04mcg.keys.";
    private final Screen parent;
    private final KeyStoreService keys;
    private final KeyTrustService trust;
    private final SessionService sessions;
    private final Krypt04McgConfig config;
    private final List<Entry> entries = new ArrayList<>();
    private final List<Button> rows = new ArrayList<>();
    private final List<DetailLine> details = new ArrayList<>();
    private String selectedOwner;
    private Component status = Component.empty();
    private boolean failed;
    private int x, y, panelWidth, panelHeight, listWidth, listOffset, detailOffset;
    private int detailTop, detailBottom, detailHeight, kemCopyY, signatureCopyY;
    private Button kemCopy, signatureCopy, verify, distrust, delete;

    public Krypt04McgKeyManagerScreen(Screen parent, KeyStoreService keys, KeyTrustService trust,
                                     SessionService sessions, Krypt04McgConfig config) {
        super(label("title"));
        this.parent = parent;
        this.keys = keys;
        this.trust = trust;
        this.sessions = sessions;
        this.config = config;
    }

    private static Component label(String key, Object... args) {
        return Component.translatable(PREFIX + key, args);
    }

    @Override
    protected void init() {
        loadEntries();
        panelWidth = Math.min(660, width - 16);
        panelHeight = Math.min(360, height - 16);
        x = (width - panelWidth) / 2;
        y = (height - panelHeight) / 2;
        listWidth = Math.min(172, panelWidth / 3);
        detailTop = y + 34;
        detailBottom = y + panelHeight - 86;
        rows.clear();
        for (int i = 0; i < Math.max(1, (panelHeight - 106) / 22); i++) {
            final int slot = i;
            rows.add(addRenderableWidget(Button.builder(Component.empty(), button -> {
                selectedOwner = entries.get(listOffset + slot).identity().owner();
                detailOffset = 0;
                refreshSelection();
            }).bounds(x + 6, y + 50 + i * 22, listWidth - 12, 20).build()));
        }
        int rightX = x + listWidth + 12;
        int rightWidth = panelWidth - listWidth - 24;
        kemCopy = addRenderableWidget(Button.builder(label("copy"), button -> copy(false))
                .bounds(rightX, detailTop, 64, 20).build());
        signatureCopy = addRenderableWidget(Button.builder(label("copy"), button -> copy(true))
                .bounds(rightX, detailTop, 64, 20).build());
        int actionWidth = (rightWidth - 8) / 3;
        int actionY = y + panelHeight - 78;
        verify = addRenderableWidget(Button.builder(label("verify"), button -> verify())
                .bounds(rightX, actionY, actionWidth, 20).build());
        distrust = addRenderableWidget(Button.builder(label("distrust"), button -> distrust())
                .bounds(rightX + actionWidth + 4, actionY, actionWidth, 20).build());
        delete = addRenderableWidget(Button.builder(label("delete"), button -> delete())
                .bounds(rightX + (actionWidth + 4) * 2, actionY, actionWidth, 20).build());
        int footerWidth = (panelWidth - 24) / 3;
        int footerY = y + panelHeight - 30;
        addRenderableWidget(Button.builder(label("import"), button -> importKey())
                .bounds(x + 8, footerY, footerWidth, 20).build());
        addRenderableWidget(Button.builder(label("export"), button -> exportKey())
                .bounds(x + 12 + footerWidth, footerY, footerWidth, 20).build());
        addRenderableWidget(Button.builder(label("regenerate"), button -> regenerate())
                .bounds(x + 16 + footerWidth * 2, footerY, footerWidth, 20).build());
        addRenderableWidget(Button.builder(Component.literal("×"), button -> onClose())
                .bounds(x + panelWidth - 24, y + 4, 20, 20).build());
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).identity().owner().equalsIgnoreCase(selectedOwner)) {
                if (i < listOffset) listOffset = i;
                if (i >= listOffset + rows.size()) listOffset = i - rows.size() + 1;
                break;
            }
        }
        refreshSelection();
    }

    private void loadEntries() {
        entries.clear();
        try {
            PublicIdentity own = keys.ownPublicIdentity();
            entries.add(new Entry(own, null));
            Set<String> owners = new HashSet<>();
            owners.add(own.owner().toLowerCase(Locale.ROOT));
            for (PublicIdentity identity : keys.listPublicIdentities().stream()
                    .sorted(Comparator.comparing(PublicIdentity::owner, String.CASE_INSENSITIVE_ORDER)).toList()) {
                if (owners.add(identity.owner().toLowerCase(Locale.ROOT))) {
                    entries.add(new Entry(identity, trust.trustState(identity.owner(), identity)));
                }
            }
        } catch (Exception e) {
            // Keep local identity accessible, but never offer trust actions for unreadable records.
            entries.removeIf(entry -> !entry.own());
            error(e);
        }
        if (entries.stream().noneMatch(entry -> entry.identity().owner().equalsIgnoreCase(
                selectedOwner == null ? "" : selectedOwner))) {
            selectedOwner = entries.isEmpty() ? null : entries.getFirst().identity().owner();
        }
    }

    private Entry selected() {
        return entries.stream().filter(entry -> entry.identity().owner().equalsIgnoreCase(
                selectedOwner == null ? "" : selectedOwner)).findFirst().orElse(null);
    }

    private void refreshSelection() {
        listOffset = Math.clamp(listOffset, 0, Math.max(0, entries.size() - rows.size()));
        refreshRows();
        Entry entry = selected();
        boolean peer = entry != null && !entry.own();
        verify.active = peer;
        distrust.active = peer && entry.state() != TrustState.DISTRUSTED;
        delete.active = peer;
        details.clear();
        int rightWidth = panelWidth - listWidth - 24;
        if (entry != null) {
            PublicIdentity identity = entry.identity();
            kemCopy.setTooltip(Tooltip.create(label("kem_fingerprint").copy()
                    .append(Component.literal(identity.kemPublicKey().fingerprint()))));
            signatureCopy.setTooltip(Tooltip.create(label("signature_fingerprint").copy()
                    .append(Component.literal(identity.signaturePublicKey().fingerprint()))));
            detailHeight = 0;
            appendDetail(Component.literal(identity.owner()), rightWidth, 0xE8F3FF);
            detailHeight += 6;
            appendDetail(label("trust", entry.own() ? label("my_identity") : trustLabel(entry.state())),
                    rightWidth, entry.own() ? 0x8DDBA4 : trustColor(entry.state()));
            appendDetail(Component.literal("KEM: " + identity.kemPublicKey().algorithm()), rightWidth, 0xAFC4D6);
            appendDetail(Component.literal("SIG: " + identity.signaturePublicKey().algorithm()), rightWidth, 0xAFC4D6);
            detailHeight += 10;
            appendDetail(label("kem_fingerprint"), rightWidth, 0xAFC4D6);
            appendDetail(Component.literal(identity.kemPublicKey().fingerprint()), rightWidth, 0xE8F3FF);
            kemCopyY = detailHeight + 3;
            detailHeight = kemCopyY + 28;
            appendDetail(label("signature_fingerprint"), rightWidth, 0xAFC4D6);
            appendDetail(Component.literal(identity.signaturePublicKey().fingerprint()), rightWidth, 0xE8F3FF);
            signatureCopyY = detailHeight + 3;
            detailHeight = signatureCopyY + 24;
        } else {
            detailHeight = 0;
        }
        refreshCopyButtons();
    }

    private void appendDetail(Component text, int width, int color) {
        for (var line : font.split(text, Math.max(1, width))) {
            details.add(new DetailLine(line, detailHeight, color));
            detailHeight += 11;
        }
    }

    private void refreshRows() {
        for (int i = 0; i < rows.size(); i++) {
            Button row = rows.get(i);
            int index = listOffset + i;
            row.visible = index < entries.size();
            if (row.visible) {
                Entry entry = entries.get(index);
                String marker = entry.own() ? "●" : switch (entry.state()) {
                    case VERIFIED -> "✓";
                    case TOFU_TRUSTED -> "◇";
                    case DISTRUSTED -> "⚠";
                    case UNTRUSTED -> "?";
                };
                row.setMessage(Component.literal(marker + " " + entry.identity().owner())
                        .withStyle(style -> style.withColor(entry.own() ? 0x8DDBA4 : trustColor(entry.state()))));
                row.active = !entry.identity().owner().equalsIgnoreCase(selectedOwner);
                row.setTooltip(Tooltip.create(entry.own() ? label("my_identity") : trustLabel(entry.state())));
            }
        }
    }

    private void refreshCopyButtons() {
        detailOffset = Math.clamp(detailOffset, 0, Math.max(0, detailHeight - (detailBottom - detailTop)));
        positionCopyButton(kemCopy, kemCopyY);
        positionCopyButton(signatureCopy, signatureCopyY);
    }

    private void positionCopyButton(Button button, int offset) {
        button.setY(detailTop + offset - detailOffset);
        button.visible = selected() != null && button.getY() >= detailTop && button.getBottom() <= detailBottom;
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(x, y, x + panelWidth, y + panelHeight, 0xE812171C);
        graphics.fill(x, y, x + panelWidth, y + 28, 0xF01B2730);
        graphics.fill(x, y + 28, x + listWidth, y + panelHeight - 52, 0xD91D252D);
        graphics.fill(x, y + panelHeight - 52, x + panelWidth, y + panelHeight - 51, 0xFF344952);
        graphics.nextStratum();
        // GuiGraphicsExtractor requires ARGB; zero alpha skips text rendering.
        graphics.text(font, title, x + 10, y + 10, 0xFFE8F3FF, false);
        graphics.text(font, label("identities"), x + 8, y + 35, 0xFFAFC4D6, false);
        graphics.enableScissor(x + listWidth + 12, detailTop, x + panelWidth - 12, detailBottom);
        for (DetailLine line : details) {
            graphics.text(font, line.text(), x + listWidth + 12,
                    detailTop + line.y() - detailOffset, line.color() | 0xFF000000, false);
        }
        graphics.disableScissor();
        if (detailHeight > detailBottom - detailTop) {
            int trackHeight = detailBottom - detailTop;
            int thumbHeight = Math.max(10, trackHeight * trackHeight / detailHeight);
            int thumbY = detailTop + detailOffset * (trackHeight - thumbHeight) / (detailHeight - trackHeight);
            graphics.fill(x + panelWidth - 5, thumbY, x + panelWidth - 3, thumbY + thumbHeight, 0xFF5D8195);
        }
        if (!rows.isEmpty() && entries.size() > rows.size()) {
            graphics.text(font, (listOffset + 1) + "–" + Math.min(entries.size(), listOffset + rows.size())
                    + "/" + entries.size(), x + 8, y + panelHeight - 64, 0xFFAFC4D6, false);
        }
        graphics.enableScissor(x + 8, y + panelHeight - 48, x + panelWidth - 8, y + panelHeight - 33);
        graphics.text(font, status, x + 8, y + panelHeight - 45, failed ? 0xFFFF9090 : 0xFF8DDBA4, false);
        graphics.disableScissor();
        if (mouseY >= y + panelHeight - 48 && mouseY < y + panelHeight - 33) {
            graphics.setTooltipForNextFrame(font, status, mouseX, mouseY);
        }
        super.extractRenderState(graphics, mouseX, mouseY, partialTick);
    }

    @Override
    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (mouseX >= x && mouseX < x + listWidth && mouseY >= y + 28 && mouseY < y + panelHeight - 52) {
            listOffset = Math.clamp(listOffset - (int) Math.signum(scrollY), 0, Math.max(0, entries.size() - rows.size()));
            refreshRows();
            return true;
        }
        if (mouseX >= x + listWidth && mouseX < x + panelWidth && mouseY >= detailTop && mouseY < detailBottom) {
            detailOffset -= (int) Math.signum(scrollY) * 22;
            refreshCopyButtons();
            return true;
        }
        return super.mouseScrolled(mouseX, mouseY, scrollX, scrollY);
    }

    private void copy(boolean signature) {
        Entry entry = selected();
        if (entry == null) return;
        Minecraft.getInstance().keyboardHandler.setClipboard(signature
                ? entry.identity().signaturePublicKey().fingerprint() : entry.identity().kemPublicKey().fingerprint());
        success(label("copied"));
    }

    private void importKey() {
        openDialog("import", label("import_help"), List.of(label("player"), label("import_data")), values -> {
            PublicIdentity imported = keys.importPublicIdentity(values.get(0).trim(), values.get(1));
            trust.rememberTofu(imported.owner(), imported);
            selectedOwner = imported.owner();
            success(Component.translatable("text.krypt04mcg.command.key_imported_tofu", imported.owner()));
        });
    }

    private void exportKey() {
        try {
            var exported = keys.exportOwnPublicFile();
            Minecraft.getInstance().keyboardHandler.setClipboard(exported.path().toString());
            success(label("exported", exported.path().toString()));
        } catch (Exception e) {
            error(e);
        }
    }

    private void verify() {
        Entry entry = selected();
        if (entry == null || entry.own()) return;
        openDialog("verify", label("verify_help", entry.identity().owner()), List.of(label("fingerprint_pair")), values -> {
            PublicIdentity identity = currentIdentity(entry.identity());
            if (!trust.fingerprintMatches(identity, values.getFirst())) {
                throw new IllegalStateException(Component.translatable("text.krypt04mcg.command.error.fingerprint_mismatch",
                        identity.owner()).getString());
            }
            trust.markVerified(identity.owner(), identity);
            success(Component.translatable("text.krypt04mcg.command.key_verified", identity.owner()));
        });
    }

    private void distrust() {
        Entry entry = selected();
        if (entry == null || entry.own()) return;
        try {
            PublicIdentity identity = currentIdentity(entry.identity());
            trust.markDistrusted(identity.owner(), identity);
            success(Component.translatable("text.krypt04mcg.command.key_distrusted", identity.owner()));
            rebuildWidgets();
        } catch (Exception e) {
            error(e);
        }
    }

    private void delete() {
        Entry entry = selected();
        if (entry == null || entry.own()) return;
        openDialog("delete", label("delete_help", entry.identity().owner()), List.of(), values -> {
            keys.removePublicIdentity(entry.identity().owner());
            // Match CommandRegistrar: permit retrying cleanup after partial I/O failure.
            trust.forget(entry.identity().owner());
            sessions.clear(entry.identity().owner());
            success(Component.translatable("text.krypt04mcg.command.key_deleted", entry.identity().owner()));
        });
    }

    private void regenerate() {
        String fingerprint = keys.regenerationFingerprint();
        openDialog("regenerate", label("regenerate_help", config.kemAlgorithm.identifier(),
                config.signatureAlgorithm.identifier(), fingerprint), List.of(label("current_fingerprint")), values -> {
            var regenerated = keys.regenerate(values.getFirst(), config.kemAlgorithm, config.signatureAlgorithm);
            selectedOwner = regenerated.kemPublicKey().owner();
            success(label("regenerated"));
        });
    }

    private PublicIdentity currentIdentity(PublicIdentity displayed) throws Exception {
        PublicIdentity current = keys.findPublicIdentity(displayed.owner()).orElseThrow(() -> new IllegalStateException(
                Component.translatable("text.krypt04mcg.error.no_public_key", displayed.owner()).getString()));
        if (!KeyTrustService.fingerprintPair(current).equals(KeyTrustService.fingerprintPair(displayed))) {
            throw new IllegalStateException(label("changed").getString());
        }
        return current;
    }

    private void success(Component message) {
        status = message;
        failed = false;
    }

    private void error(Exception e) {
        status = Component.translatable("text.krypt04mcg.error.generic", e.getMessage());
        failed = true;
    }

    private void openDialog(String action, Component help, List<Component> fields, DialogAction handler) {
        Minecraft.getInstance().gui.setScreen(new KeyDialog(label(action), help, fields, handler));
    }

    @Override
    public void onClose() {
        Minecraft.getInstance().gui.setScreen(parent);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    private static Component trustLabel(TrustState state) {
        return Component.translatable("text.krypt04mcg.trust." + state.name());
    }

    private static int trustColor(TrustState state) {
        return switch (state) {
            case VERIFIED -> 0x8DDBA4;
            case TOFU_TRUSTED -> 0xAFC4D6;
            case DISTRUSTED -> 0xFF9090;
            case UNTRUSTED -> 0xD8A657;
        };
    }

    private record Entry(PublicIdentity identity, TrustState state) {
        private boolean own() { return state == null; }
    }

    private record DetailLine(FormattedCharSequence text, int y, int color) { }

    @FunctionalInterface
    private interface DialogAction {
        void run(List<String> values) throws Exception;
    }

    private final class KeyDialog extends Screen {
        private final Component help;
        private final List<Component> fields;
        private final DialogAction handler;
        private final List<EditBox> inputs = new ArrayList<>();
        private Component error = Component.empty();
        private int left, top, dialogWidth, bottom, helpBottom, helpOffset;

        private KeyDialog(Component title, Component help, List<Component> fields, DialogAction handler) {
            super(title);
            this.help = help;
            this.fields = fields;
            this.handler = handler;
        }

        @Override
        protected void init() {
            List<String> saved = inputs.stream().map(EditBox::getValue).toList();
            inputs.clear();
            dialogWidth = Math.min(500, width - 24);
            left = (width - dialogWidth) / 2;
            int helpHeight = font.split(help, dialogWidth - 24).size() * 11;
            int dialogHeight = Math.min(height - 16, 78 + helpHeight + fields.size() * 36);
            top = (height - dialogHeight) / 2;
            bottom = top + dialogHeight;
            helpBottom = bottom - 48 - fields.size() * 36;
            helpOffset = Math.clamp(helpOffset, 0, Math.max(0, helpHeight - (helpBottom - top - 28)));
            for (int i = 0; i < fields.size(); i++) {
                EditBox input = new EditBox(font, left + 12, helpBottom + 14 + i * 36, dialogWidth - 24, 20, fields.get(i));
                input.setMaxLength(fields.size() == 2 ? (i == 0 ? 32 : 1_048_576) : 512);
                input.setHint(fields.get(i));
                if (i < saved.size()) input.setValue(saved.get(i));
                inputs.add(addRenderableWidget(input));
            }
            Button confirm = addRenderableWidget(Button.builder(label("confirm"), button -> submit())
                    .bounds(left + 12, bottom - 28, (dialogWidth - 28) / 2, 20).build());
            Button cancel = addRenderableWidget(Button.builder(Component.translatable("gui.cancel"), button -> onClose())
                    .bounds(left + 16 + (dialogWidth - 28) / 2, bottom - 28, (dialogWidth - 28) / 2, 20).build());
            if (!inputs.isEmpty()) {
                Runnable update = () -> confirm.active = inputs.stream().allMatch(input -> !input.getValue().isBlank());
                inputs.forEach(input -> input.setResponder(value -> update.run()));
                update.run();
                setInitialFocus(inputs.getFirst());
            } else {
                setInitialFocus(cancel);
            }
        }

        private void submit() {
            if (inputs.stream().anyMatch(input -> input.getValue().isBlank())) return;
            try {
                handler.run(inputs.stream().map(EditBox::getValue).toList());
                detailOffset = 0;
                onClose();
            } catch (Exception e) {
                error = Component.translatable("text.krypt04mcg.error.generic", e.getMessage());
            }
        }

        @Override
        public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float partialTick) {
            graphics.fill(left, top, left + dialogWidth, bottom, 0xF012171C);
            graphics.nextStratum();
            graphics.text(font, title, left + 12, top + 10, 0xFFE8F3FF, false);
            graphics.enableScissor(left + 12, top + 28, left + dialogWidth - 12, helpBottom);
            int lineY = top + 28 - helpOffset;
            for (var line : font.split(help, dialogWidth - 24)) {
                graphics.text(font, line, left + 12, lineY, 0xFFAFC4D6, false);
                lineY += 11;
            }
            graphics.disableScissor();
            int helpHeight = font.split(help, dialogWidth - 24).size() * 11;
            int viewportHeight = helpBottom - top - 28;
            if (helpHeight > viewportHeight) {
                int thumbHeight = Math.max(8, viewportHeight * viewportHeight / helpHeight);
                int thumbY = top + 28 + helpOffset * (viewportHeight - thumbHeight) / (helpHeight - viewportHeight);
                graphics.fill(left + dialogWidth - 7, thumbY, left + dialogWidth - 5,
                        thumbY + thumbHeight, 0xFF5D8195);
            }
            for (int i = 0; i < fields.size(); i++) {
                graphics.text(font, fields.get(i), left + 12, helpBottom + 3 + i * 36, 0xFFAFC4D6, false);
            }
            graphics.enableScissor(left + 12, bottom - 43, left + dialogWidth - 12, bottom - 30);
            graphics.text(font, error, left + 12, bottom - 41, 0xFFFF9090, false);
            graphics.disableScissor();
            if (mouseY >= bottom - 43 && mouseY < bottom - 30) {
                graphics.setTooltipForNextFrame(font, error, mouseX, mouseY);
            }
            super.extractRenderState(graphics, mouseX, mouseY, partialTick);
        }

        @Override
        public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
            if (mouseX >= left && mouseX < left + dialogWidth && mouseY >= top + 28 && mouseY < helpBottom) {
                int helpHeight = font.split(help, dialogWidth - 24).size() * 11;
                helpOffset = Math.clamp(helpOffset - (int) Math.signum(scrollY) * 22,
                        0, Math.max(0, helpHeight - (helpBottom - top - 28)));
                return true;
            }
            return super.mouseScrolled(mouseX, mouseY, scrollX, scrollY);
        }

        @Override
        public boolean keyPressed(KeyEvent event) {
            if (inputs.stream().anyMatch(EditBox::isFocused) && (event.key() == 257 || event.key() == 335)) {
                submit();
                return true;
            }
            return super.keyPressed(event);
        }

        @Override
        public void onClose() {
            Minecraft.getInstance().gui.setScreen(Krypt04McgKeyManagerScreen.this);
        }

        @Override
        public boolean isPauseScreen() { return false; }
    }
}
