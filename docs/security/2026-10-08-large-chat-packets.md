# Large encrypted chat packets — 2026-10-08

## Capacity and time-window mismatch

Client 0.28.0 allowed only 512 fragments; relay 1.8.3 defaulted to 256. At the default 180-character payload, the complete binary packet capacities were 69,120 and 34,560 bytes respectively. A 64 KiB body plus a large post-quantum signature and KEM encapsulation could exceed both. A higher character-cache budget alone would not fix this.

Client 0.29.0 and relay 1.9.0 accept a complete encrypted chat packet of up to 262,144 bytes and 2,048 fragments. The packet budget includes metadata, nonce, KEM encapsulation, AEAD body and signature. Base64URL needs at most 349,526 unpadded characters. At the default 180-character slice the upper-bound packet is 1,942 fragments. Smaller configured slices grow as necessary; the 256-character wire line limit remains, and excessively long custom prefixes can still prevent transmission. Four-digit indices/totals are accepted; old clients retain the 512-fragment limit and must be upgraded.

Vanilla chat/commands are paced at least one second apart. A large packet would exceed the fixed two-minute receive lifetime, independently of memory capacity. When configured pacing cannot fit, an available chat custom-payload transport is selected for that batch at 50 ms pacing. Without the channel, admission fails before sending with an actionable error. Queue estimates include existing work and client tick granularity; stalled sends expire before another stale submission. Transport and pacing are captured per batch. The sender's queue budget is at most 110 seconds and also respects its configured authenticated packet-age setting with a margin. Remote receivers can configure stricter age windows independently; sender success is not an acknowledgement.

Receive expiry, signature verification, identity checks, authenticated freshness and replay/session validation remain in place. Large messages are not admitted by stretching an unauthenticated receive deadline. Raw API/file stream formats and separate stream limits are unaffected.

## Buffered-text quotas removed at user request

Relay 1.9.0 removes the former global 4,194,304-character, per-player 1,048,576-character and completed-outbox 1,048,576-character quotas. There is no replacement aggregate buffered-character quota in the client. Per-packet size remains bounded while assembling, including validation of the decoded relay packet. Oversized packets remove only their own assembly; completion, invalid completed encoding, expiry and disconnect release state.

Count bounds remain: default 128 pending client/relay messages, 16 per transport source/player UUID, and 64 completed relay-outbox jobs. Fixed receive expiry, relay outbox expiry, queue fragment limits and ingress/egress traffic budgets remain. New IDs do not evict admitted messages. More concurrent large packets now retain more memory; this is a deliberate availability tradeoff, not a denial-of-service guarantee. Relay administrators can lower the global pending-message count. Existing relay config values are preserved: set `max-fragments-per-message: 2048` and retain the default 120-second timeout for large-packet support.

## Validation

Versioned Fabric and NeoForge builds passed 219 selected Fabric tests and 119 NeoForge tests, with zero failures/errors/skips. Relay Maven verification passed 128 tests with zero failures/errors/skips. The Fabric run includes real encryption, fragmentation, reassembly, signature verification and decryption of a full 64 KiB uncompressed body with SLH-DSA-SHA2-256f+Ed448 (49,982-byte signature) and HQC-256+X448 KEM. Boundary tests round-trip 256 KiB, reject one extra byte, process four-digit fragment indices, reject oversize assemblies without evicting other senders, and verify maximum batch pacing/deadline cancellation. Production send-service tests select the custom transport and reject unavailable large-message transport on both loaders.

Relay tests accept more than the former global and per-player character quotas using valid 256-character-or-shorter wire fragments, retain count and deadline tests, round-trip a 256 KiB packet at 50 ms simulated pacing and reject a decoded packet one byte over the limit. Completed-outbox tests exceed the former text quota and accept 2,048 fragments while retaining message count and expiry checks.

Reverse-forwarding 1.3.2 also built against the new core JAR and passed 52 test executions (17 root, 32 regression and three IPv6 preference repeats). The documentation build, HTTP content checks for five updated pages and 17 internal page links passed.

Actual game/Spigot/ProtocolLib networking and rendering, the full costly PQ algorithm matrix, remote Actions completion and existing dependency alerts are outside this validation. Published tag layouts retain the existing release workflows.
