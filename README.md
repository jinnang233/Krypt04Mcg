# Krypt04Mcg

[![Build and Release](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/release.yml/badge.svg)](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/release.yml) [![CodeQL](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/github-code-scanning/codeql) [![Generate Gradle Wrapper](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/generate-wrapper.yml/badge.svg)](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/generate-wrapper.yml) 

Krypt04Mcg (Aka: Krypt04Msg) means "Crypto for message (MineCraft message)".

The project was renamed from ObscuraLink-MC/ObscuraLink because "Obscura" is already used by a Minecraft modding organization. Krypt04Mcg is the chosen name to avoid that naming conflict.

> [!WARNING]
> This codebase was **generated with AI assistance**. Review the implementation carefully, especially the cryptography, key storage, networking behavior, and dependency configuration, before using it in any real environment.
> 
> If possible, please run it in an **ISOLATED** environment, such as a virtual machine, to avoid potential security risks from build artifacts, such as the possibility that the maintainer’s computer has been infected with malware.
>
> If you discover any code security issues, or any copyright or licensing concerns, please report them in Issues. Thank you for your understanding.

> [!WARNING]
> Krypt04Mcg is **EXPERIMENTAL** software and has not undergone independent security auditing. The protocol, implementation, and cryptographic design **may contain vulnerabilities or design flaws**. Do not rely on this mod to protect highly sensitive, important, or production-critical data. If you require mature and battle-tested end-to-end encrypted communication, consider using established tools such as Signal or SimpleX instead.

## Disclaimer

Krypt04Mcg is an **EXPERIMENTAL** mod project. Its build environment, release artifacts, dependencies, and runtime behavior are provided as-is, with **NO GUARANTEE** that they are secure, trustworthy, virus-free, or suitable for any particular use. Before installing or running any downloaded artifact, **scan it with VirusTotal** or a comparable malware-scanning service whenever possible.

**Never use this project in production environments, and never use it to protect sensitive, important, private, regulated, or high-value data. This project is not expected to receive active long-term maintenance, security response, or compatibility updates.**

Krypt04Mcg is a Fabric client mod that transports post-quantum encrypted chat packets through ordinary Minecraft chat. It uses compact binary packets, Base64URL transport encoding, automatic fragmentation, TOFU public-key storage, and authenticated AEAD encryption.

## Features

- Client-side `/k04m` command tree, also available as `/Krypt04Mcg:enc` and `/Krypt04Mcg:k04m`.
- Configurable CMCE and ML-KEM key parameter sets.
- Configurable Falcon and ML-DSA signature parameter sets.
- AES-256-GCM or ChaCha20-Poly1305 with a random 96-bit nonce per message.
- HKDF-SHA256 derives AEAD keys from KEM shared secrets.
- Optional signature verification for signed packets.
- Public-key import/export with Trust On First Use checks.
- Automatic chat fragmentation and out-of-order reassembly.
- Timeout cleanup and bounded receive caches.
- Optional Cloth AutoConfig-backed configuration.

## Supported Versions

This implementation targets:

- Minecraft Java `26.2`
- Fabric Loader `0.19.5`
- Fabric API `0.160.0+26.2`
- Loom `1.17.20`
- Java `25`

Compatibility Notes: Minecraft/Fabric 26.1+ uses Mojang's unobfuscated names and the non-remapping Fabric Loom plugin. Krypt04Mcg keeps its protocol and crypto layers independent from Minecraft APIs so future 26.x ports should mostly be limited to the client entrypoint, command, and chat-event adapters.

## Build

```bash
gradle build
```

If you prefer a wrapper, generate one with a local Gradle install:

```bash
gradle wrapper
./gradlew build
```

## Releases

GitHub Actions builds the mod and publishes release artifacts automatically when a tag matching `v*` is pushed:

```bash
git tag v0.10.0
git push origin v0.10.0
```

The release workflow can also be triggered manually from the Actions tab. Manual builds are published under generated `snapshot-YYYYMMDD-HHMMSS` tags.

Release artifacts include:

- the mod JAR from `build/libs`
- a detached `.jar.sign` signature for each release JAR
- `public_key.pem` for signature verification

To verify a downloaded release JAR:

```bash
openssl dgst -verify public_key.pem -signature krypt04mcg-0.8.7.jar.sign krypt04mcg-0.8.7.jar
```

## License

Krypt04Mcg is licensed under the BSD Zero Clause License (`0BSD`), a very permissive license with no attribution requirement.

## Run Client

```bash
gradle runClient
```

## Install

Build the project, then copy `build/libs/krypt04mcg-<version>.jar` into the client `mods` directory together with Fabric API. Cloth Config is optional and only needed for the ModMenu settings screen.

## Key Storage

Krypt04Mcg stores data under:

```text
config/krypt04mcg/accounts/<minecraft-uuid>/
  keys/
    private/local.json
    public/*.json
  export/
  sessions/
  cache/
  secrets/master.key
```

Private and public key material are stored separately and scoped to the active Minecraft account. Private keys, trust bindings, session secrets, and enabled conversation history are encrypted with AES-256-GCM. On Windows, the storage master key is protected with per-user DPAPI; other platforms use an explicitly owner-only master-key file. Sensitive writes are atomic and owner-only permissions are applied where the platform supports them. Public-key records include algorithm, owner, UUID, a full SHA-256 fingerprint, creation time, and Base64URL key data.
`/k04m key export` writes your shareable public key JSON inside the active account's `export` directory.

The KEM and signature selections only apply when no local key exists or when a key is explicitly regenerated. Changing the configuration never rewrites an existing key. Encryption, signing, verification, and decryption resolve algorithms from key records and packet algorithm identifiers rather than assuming the current configuration.

Supported key selections are all ten Bouncy Castle CMCE parameter sets, ML-KEM-512/768/1024, Falcon-512/1024,
ML-DSA-44/65/87, all 24 SLH-DSA variants (the 12 SHA2/SHAKE parameter sets in both pure and pre-hash forms),
all three SQIsign parameter sets (`SQIsign-lvl1`, `SQIsign-lvl3`, and `SQIsign-lvl5`),
and all 44 SNOVA variants. SNOVA includes the base parameter sets `24-5-4`, `24-5-5`, `25-8-3`,
`29-6-5`, `37-8-4`, `37-17-2`, `49-11-3`, `56-25-2`, `60-10-4`, `66-15-3`, and `75-33-2`,
each with `SSK`, `ESK`, `SHAKE-SSK`, and `SHAKE-ESK` variants (for example, `SNOVA-24-5-4-SSK`).
The long-term defaults remain `CMCE/mceliece348864`, `Falcon-512`, and `AES-256-GCM`. The independently configurable ephemeral KEM used only by `/k04m exchange` and `/k04m etell` sessions defaults to `ML-KEM-768`.

## Commands

```text
/k04m tell <receiver> <message>
/k04m stell <receiver> <message>
/k04m exchange <receiver>
/k04m etell <receiver> <message>
/k04m gtell <group> <message>
/k04m group create <name> <members>
/k04m group list
/k04m group delete <name>
/k04m resend [messageId]
/k04m session list
/k04m session clear <player>
/k04m session refresh <player>
/k04m showalgs
/k04m status <player>
/k04m key list
/k04m key fingerprint <player>
/k04m key export
/k04m key import <player> <data-or-file>
/k04m key delete <player>
/k04m key remove <player>
/k04m key regenerate
/k04m key regenerate <current-kem-fingerprint>
/k04m key verify <player> <kem-fingerprint>:<signature-fingerprint>
/k04m key trust <player>
/k04m key distrust <player>
```

`/k04m status <player>` shows that player's long-term KEM and signature algorithms from their stored public keys, or unknown when no public key is available. The separately labeled local configuration describes your own settings. The public key export does not include the other player's ephemeral KEM or AEAD configuration; stored keys do not report subsequent remote key changes automatically.

Import flow:

1. The other player runs `/k04m key export`.
2. They send you the exported JSON file through a trusted side channel and tell you the printed fingerprints.
3. You run `/k04m key import <player> <file-or-json>`.
4. First import is trusted automatically. If a key changes later, Krypt04Mcg refuses to overwrite it silently. Use `/k04m key delete <player>` (alias: `/k04m key remove <player>`) to remove that player's imported public keys, trust record, and saved session before importing a replacement. Player names are case-insensitive; your own keys cannot be deleted this way. A replacement starts with TOFU trust and must be verified again.
5. To mark the identity `VERIFIED`, compare both full fingerprints out of band and pass their colon-separated pair to `/k04m key verify`.

Regeneration flow:

1. Select the replacement KEM and signature parameter sets in the mod configuration.
2. Run `/k04m key regenerate`; the mod prints the current KEM fingerprint and the exact confirmation command.
3. Run `/k04m key regenerate <current-kem-fingerprint>` to replace both local key pairs.
4. Export and redistribute the new public key. Existing peers will reject it as a TOFU key change until they deliberately replace the old key.

## Protocol Format

Packets are compact binary and then Base64URL encoded for chat transport. The binary packet layout is:

```text
u8   protocolVersion
u8   packetType
u8   flags
u16  senderLength
bytes senderUtf8
u16  receiverLength
bytes receiverUtf8
i64  timestampMillis
 16   messageId
 [u16 kemAlgorithmLength + bytes kemAlgorithmUtf8]
 [u16 signatureAlgorithmLength + bytes signatureAlgorithmUtf8]
u16  aeadAlgorithmLength
bytes aeadAlgorithmUtf8
u16  hkdfAlgorithmLength
bytes hkdfAlgorithmUtf8
u16  nonceLength
bytes nonce
i32  kemCiphertextLength
bytes kemCiphertext
i32  ciphertextLength
bytes ciphertext
i32  signatureLength
bytes signature
```

Protocol v4 adds `u16 sessionIdLength + bytes sessionIdUtf8` and `i64 sequence` immediately after message ID for SESSION_MESSAGE only, and omits its signature length/data entirely. SESSION_EXCHANGE retains its PQ signature. Other packet layouts remain as in v3; v1–v3 decoding is retained for non-session messages.

The bracketed v3 fields are conditional: KEM identifiers are omitted from session messages, and signature identifiers are omitted from unsigned messages. Protocol v3 also removes the obsolete packet-level fragment index/total fields. The decoder retains the original v1/v2 layout and AAD rules for compatibility.

Packet types:

- `1`: KEM encrypted message.
- `2`: signed KEM encrypted message.
- `3`: session exchange.
- `4`: session message.

## Security Design

- AES/ECB is not used.
- The packet-selected supported AEAD is used with a fresh random nonce per encrypted message.
- `SecureRandom` generates message IDs, nonces, KEM randomness, and session material.
- KEM shared secrets are never used directly as AEAD keys.
- HKDF-SHA256 derives AEAD keys with the message ID as salt.
- Protocol v3 AEAD AAD covers protocol version, packet type, flags, sender, receiver, timestamp, message ID, and all present algorithm identifiers. Timestamp tampering therefore fails even for unsigned packets.
- Incoming packets select their supported algorithms from the authenticated protocol identifiers; the KEM and signature identifiers must match the corresponding stored key records.
- Signatures cover AAD plus timestamp, nonce, KEM encapsulation, and ciphertext.
- Decryption rejects wrong receivers before attempting plaintext display.
- The authenticated packet sender must match the outer Minecraft sender; transports without an authenticated sender accept signed packets or AEAD-authenticated messages from an established, identity-bound session.
- `DISTRUSTED` identities are rejected before decryption or session state changes. Verified trust records bind the player name and both public-key fingerprints.
- Accepted timestamps have a bounded freshness window, replay records are retained per sender, and session messages authenticate the session epoch and a monotonic sequence number before counters advance.
- Decryption failures do not display garbage plaintext.
- Signature failures are displayed explicitly as invalid.

## Fragment Design

Each chat fragment has this form:

```text
[KRYPT04MCG] <messageIdHex> <index> <total> <payload>
```

The receiver supports out-of-order fragments, ignores duplicate fragments, cleans up timed-out partial messages, caps pending messages, and rejects excessive fragment counts.

## Optional Payload Channel

Krypt04Mcg remains a client-side mod. Servers do not need to install any plugin or mod for the default chat transport, and the optional payload channel is not used for mandatory login or configuration negotiation.

If a server plugin wants to relay fragments without normal chat, it can declare support for this play-stage custom payload channel:

```text
channel id: krypt04mcg:chat_fragment
direction C2S: client -> server
payload fields C2S:
  string receiver
  string fragment
  varint version
direction S2C: server -> client
payload fields S2C:
  string sender
  string fragment
  varint version
```

The first field is direction-specific. For C2S it is the intended receiver. For S2C it is the authenticated
Minecraft sender. The server must derive the S2C `sender` from the player connection that supplied the C2S
payload; it must not accept a sender name supplied by a client or copy the C2S `receiver` into that field.

Client send mode `CUSTOM_PAYLOAD` only sends on this channel when Fabric reports the connected server can receive `krypt04mcg:chat_fragment`; otherwise the client simply skips payload sending and does not require server-side support.

## Session Design

`/k04m exchange` is a signed two-message handshake using the dedicated `SESSION_EXCHANGE` packet type. The initiator creates an in-memory one-time KEM key pair (ML-KEM-768 by default); the responder encrypts fresh session material only to that temporary public key and binds both identities, UUIDs, both fingerprint pairs, the session ID, and the request message ID into the exchange transcript. The initiator destroys the temporary private key after accepting the response or after a short timeout. Consequently, later compromise of either long-term KEM private key does not decrypt a recorded exchange response.

`/k04m etell` uses the resulting session secret with an AEAD-only `SESSION_MESSAGE` packet (no per-message PQ signature or additional HMAC). Protocol v4 carries the session ID and monotonic sequence in the packet header and authenticates them, together with sender and receiver, through AEAD AAD. The encrypted payload contains only its version and message. Old v1–v3 session messages are rejected; both peers must upgrade. `tell` and `stell` continue to use their existing long-term recipient KEM path and do not use the ephemeral KEM setting.

## GUI Chat

The encrypted chat panel can be opened with the configured Krypt04Mcg key binding. It lists imported players, recent peers, and configured groups. Group targets are shown with a `#` prefix and send through the existing group fan-out flow.

Recent plaintext conversation history is cached locally under:

```text
config/krypt04mcg/accounts/<minecraft-uuid>/cache/conversations.json
```

The encrypted cache is bounded to the most recent 300 entries and is disabled by default. It can be enabled with the `enableConversationHistory` config option. With this option disabled, the GUI still displays up to 300 live conversation entries in memory, without loading or saving conversation history on disk.

## Known Limitations

- This is a client-only chat transport. Server chat filtering, signing, rate limits, and antispam plugins may interfere with large encrypted payloads.
- Minecraft chat channels have a limited number of characters per message, so fragmentation is expected.
- First import remains TOFU-based; verify the complete KEM/signature fingerprint pair out of band for stronger protection.

## Tests

Run all unit, regression, and fuzz tests:

    ./gradlew test
    .\gradlew.bat test  # Windows

The report is written to build/reports/tests/test/index.html. GitHub Actions runs the tests
on Linux and Windows for pushes and pull requests, including Windows DPAPI storage tests.

Back up account storage as a unit. If secrets/master.key is missing, restore the original;
encrypted files cannot be recovered by generating a replacement key. Storage directories must
support owner-only permissions and must not be symbolic links or directory junctions.
System-message (shadow-listen) transport has no authenticated player identity; use signed
messages (stell, exchange) or established AEAD session messages (etell) there. Unsigned tell messages require authenticated chat or payload transport.

Implemented test coverage:

- packet encode/decode
- encrypt/decrypt
- sign/verify
- fragment/reassemble
- timeout cleanup
- wrong receiver rejection
- modified ciphertext rejection

## Public-key and file sharing over optional payload channels

These features require `CUSTOM_PAYLOAD` mode and an updated Krypt04McgRelay plugin.
The three independent optional channels are `krypt04mcg:chat_fragment`, `krypt04mcg:public_key`,
and `krypt04mcg:file_share`. Sharing does not fall back to ordinary chat when a channel is unavailable.

- `/k04m-share key` announces your public key to all online clients subscribed to the channel.
- `/k04m-share key <player>` sends your public key to a specific player.
- Recipients see the key fingerprints and clickable `[√]` and `[×]` buttons in chat.
  Keys are imported only after acceptance; rejection leaves the key store unchanged.
  Requests expire after 60 seconds or upon disconnect. Different existing keys are never overwritten.
  Acceptance establishes TOFU trust, not out-of-band verification.
- `/k04m-share file <player> <path>` sends an encrypted file with a mandatory signature. Paths may be double-quoted.
  Both players must first accept each other's public keys. The limit is **10 MiB** (10,485,760 bytes) per file.
  Both the filename and contents are encrypted and signed. Both clients must support this limit.
  File encryption uses separate limits; ordinary chat retains its 64 KiB plaintext limit.
- `enableFileSending` and `enableFileReceiving` control sending and receiving independently; **both default to false**.
  Enable them through the Cloth Config screen. Without Cloth Config, both remain disabled by default.
- Received files are saved to `received-files` within the current account's storage directory only after
  signature verification and explicit acceptance. Saved names include a random identifier and have path
  characters filtered out. Files are never opened or executed automatically.
- Set `permanentlyDisableFileSharing=true` or run `/k04m-share disable-files` to permanently disable file
  sending and receiving for the current account. This writes `file-sharing.disabled` to the account directory.
  Restarting or toggling the sending and receiving settings does not remove the lock. Anyone with write access
  to the configuration directory can still remove this local marker manually.

Transfers use chunks of 12,000 characters. Public keys allow up to four concurrent assemblies with 128 chunks each;
files allow one assembly with up to 2048 chunks. File sending is limited to four chunks per client tick and one
outgoing file at a time. Disconnecting or disabling sending clears the outgoing queue.
Assembly expires after 60 seconds. Up to four requests may await confirmation, including at most one file.
The file replay cache holds up to 1024 entries per connection; reconnect after reaching this limit to receive
more files. The relay obtains the authenticated sender name from the server connection.

Sharing messages, confirmation buttons, and settings support Simplified Chinese, Traditional Chinese, English,
German, Spanish, French, Japanese, and Korean. They follow the client language and use the configured message prefix.
