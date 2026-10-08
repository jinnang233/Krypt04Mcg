# Chat progress and sender admission — 2026-10-08

## Confirmed availability issue

The 0.27.5 receive handler only enforced a global 128-message reassembly limit. A single sender could submit the first valid-looking fragment for 128 different IDs, leaving other players unable to start a receive until expiry. These fragments are not yet cryptographically authenticated. Existing assemblies were preserved, but the global admission pool could still be monopolized.

A standalone probe against the Fabric JAR built from the v0.27.5 tag reproduces this behavior: Mallory sends 128 incomplete IDs; Alice's first fragment is not admitted. The same receive-handler calls against the fixed classes admit only 16 Mallory IDs and allow Alice to start receiving. The probe uses synthetic fragments and no real keys or remote service.

The production handler now passes the transport source to a sender-aware reassembly overload, with a case-insensitive limit of 16 per source. Shadow/system-chat input has no authenticated transport player and shares the `signed-unbound` bucket; names in the displayed chat text do not grant separate quotas. The existing 128-message/512-fragment limits and fixed two-minute lifetime still apply. The original utility overload is retained for trusted direct callers and keeps its global-only behavior.

## Connection lifecycle and progress correctness

Incoming assemblies previously survived Minecraft disconnects. Both loader entry points now clear receive assemblies, the connection-bound send queue and HUD state on disconnect and join, and when applying saved settings. This prevents old partials from consuming slots or being combined across a server change. It does not change persistent keys, trust or session storage.

Chat progress is an in-place native HUD bar. Send progress advances after the transport callback succeeds; missing payload channels throw rather than silently succeeding. Completion means local submission, not acknowledgement by the remote client. Receive completion follows existing identity, decrypt, freshness and replay/session checks; merely assembling a packet never marks it verified. Invalid or replayed packets show a failure. Idle ticks expire unfinished receives, and cleanup notifications also cover expiry during admission.

HUD state contains peer labels/counts/status only, bounded to 32 entries per direction. New IDs cannot replace active entries; terminal entries expire after three seconds and may be reclaimed earlier under pressure. Drawing is bounded to two rows per direction and clips long text to the available width. Existing progress switches independently control send/receive display. Progress is based on chat fragments, not raw API or file-stream bytes. The plaintext conversation history still records accepted/queued sends, not delivery receipts.

## Scope and validation

Regression coverage exercises actual receive-handler sender flooding, the unbound bucket, case aliases, duplicate counts, changing totals, idle/admission expiry, connection clear, verified receive and rejected replay. Queue tests cover exact successful-submission counts, pacing, transport failure, cancellation and server changes. Tracker tests cover direction isolation, ID floods, result expiry and pending-entry preservation. These shared tests also run against NeoForge's chat handler.

The versioned builds passed 218 selected Fabric tests and 106 NeoForge tests with no failures, errors or skips. Relay Maven verification passed 126 tests. Reverse-forwarding compatibility against the new core passed 52 test executions. Both client JARs contain version 0.28.0, the HUD/tracker classes and all eight matching progress localization sets; the relay JAR contains version 1.8.3. The documentation build and local HTTP checks of the release/configuration/download pages and their internal links passed.

The companion relay fix is plugin 1.8.3: sender UUID and text budgets protect its separate vanilla-chat collector. Custom payload/raw streams bypass that collector. Existing reverse-forwarding admission quotas were inspected and require no protocol change for this HUD.

This round does not validate real in-game placement, actual Minecraft/Spigot networking, Windows ACLs, the full costly PQ parameter matrix or resolution of the existing GitHub dependency alerts. Per-sender quotas mitigate single-source slot monopolization; multiple players, an untrusted server or continuous complete-packet traffic remain outside that guarantee.
