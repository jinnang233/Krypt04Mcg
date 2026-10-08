# Changelog

## 0.28.0 — 2026-10-08

### Transfer progress

- Replace per-fragment chat notices with send/receive HUD progress bars on Fabric and NeoForge, including the encrypted chat screen. Show the peer, percentage, fragment counts and queued/transferring/verifying/completed/failed/timed-out/cancelled state; completed results disappear after three seconds.
- Keep `showProgress` and `showReceiveProgress` as independent switches and respect the hidden HUD. Show at most two transfers per direction, with bounded state separated between sends and receives.
- Count only successful local transport submissions as sent. Unsupported custom-payload channels now fail and cancel remaining queued work, instead of silently reporting success. Sent progress does not acknowledge delivery to the other player.
- Report receive completion only after decoding, identity checks, decryption, freshness and replay/session validation. Duplicate fragments do not inflate counts; expiry is processed on idle ticks and attributed to the correct sender.
- Local plaintext conversation entries still represent accepted/queued sends, not delivery receipts. The HUD reports their subsequent transport state.

### Security and upgrade notes

- Limit chat reassembly to 16 pending messages per transport sender, case-insensitively, within the existing 128-message global limit. Unbound shadow-chat fragments share one bounded bucket. New IDs cannot evict admitted messages.
- Clear incoming assemblies, outgoing queues and progress on disconnect/join and configuration saves. Hexadecimal message ID case aliases share one assembly.
- No packet layout, cryptographic algorithm, JSON format or stream API change. These progress bars cover encrypted chat/session/exchange fragments; raw API and built-in file streams retain their existing behavior.
- Relay plugin 1.8.3 adds corresponding vanilla-chat sender and buffered-text quotas. k04m-reverseforward 1.3.2 remains compatible.

Details and validation limits: [chat progress and sender quotas](docs/security/2026-10-08-chat-progress-and-quotas.md). Actual game rendering/networking, Windows permissions, the full high-cost PQ matrix and existing GitHub dependency alerts are not covered by this validation.

## 0.27.5 — 2026-10-08

### Security and reliability

- Chat assemblies expire from the first received fragment, rather than allowing new indices to extend their lifetime. At capacity, new message IDs are rejected without evicting in-flight messages.
- Reject malformed chat fragments before assembly: 32-character hexadecimal IDs, decimal indices, at most 512 fragments, and unpadded Base64URL payloads.
- Group membership, sent ciphertext caches, and decryption/replay history reject symbolic links, including dangling links and linked parents, and enforce owner-only file permissions. Group and sent-cache updates use private temporary files and atomic replacement where supported.
- Built-in incoming files must complete, including authenticated EOF, within two minutes of admission. Byte progress cannot extend this deadline; cancellation releases the shared file/public-key worker. This does not impose a total duration limit on general API streams.

### Algorithm selections

- Complete the `+Ed25519` and `+Ed448` choices for every supported PQ signature parameter set, including 152 additional combinations for Falcon, ML-DSA, SLH-DSA, SQIsign and SNOVA. Both signatures remain required. Custom combinations retain their experimental format; the existing BC-native default is unchanged.

### Upgrade notes

- Fabric and NeoForge use the same version. Network layouts, public stream API, and existing JSON formats are unchanged by the security fixes.
- Move linked group/cache/history files or directories into regular local storage before use. Back up account storage as a unit, including the original master key.
- Very slow incoming files are cancelled after two minutes and may need to be retried.
- New signature choices require support on both peers; adopting a new long-term suite requires explicit key regeneration, public-key exchange and fingerprint verification.
- The relay's vanilla-chat capacity fix is released separately in Krypt04mcg-plugin 1.8.2. Reverse-forwarding protections are released in k04m-reverseforward 1.3.2; neither changes the stream wire protocol.

This is a targeted security update, not an independent security audit. Previously reported GitHub dependency alerts remain unresolved; the full high-cost PQ parameter matrix and actual game networking were not validated in this audit round.

Details: [fragment audit](docs/security/2026-10-08-audit.md), [local storage](docs/security/2026-10-08-local-storage.md), [file receive deadline](docs/security/2026-10-08-file-receive-deadline.md).
