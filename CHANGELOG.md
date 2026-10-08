# Changelog

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
