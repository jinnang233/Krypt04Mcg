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

Krypt04Mcg is a Fabric or NeoForge client mod that transports post-quantum encrypted chat packets through ordinary Minecraft chat. It uses compact binary packets, Base64URL transport encoding, automatic fragmentation, TOFU public-key storage, and authenticated AEAD encryption.

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

- Minecraft Java `26.3`
- Fabric Loader `0.19.5`
- Fabric API `0.161.0+26.3`
- Loom `1.17.20`
- NeoForge `26.3.0.16-beta` (separate client build)
- Java `25`

The NeoForge build shares the protocol, cryptography, and storage code with Fabric. It requires no server installation for chat transport. Custom payload and public-key sharing still require a server relay that advertises the corresponding channels.

NeoForge's optional Cloth Config integration uses `26.3.158` for Minecraft 26.3 and detects its NeoForge mod ID, `cloth_config`. Install Cloth Config separately to enable the config screen. JSON settings are available with or without Cloth Config.

## User-configurable runtime limits

Settings are stored in `config/krypt04mcg.json` on both Fabric and NeoForge.
The file is created with defaults on first startup even without Cloth Config.
Edit it while the game is closed, then restart the client. Existing files may omit
new fields; omitted fields retain their defaults. Invalid JSON is logged, defaults
are used for that launch, and the invalid file is preserved for correction.

With Cloth Config installed, the same settings are available in the mod settings
screen. Saving updates the running configuration. New queue limits apply when
admitting work; history/cache limits apply on the next write; already scheduled
acknowledgement deadlines keep their original value. Reducing a queue limit does
not cancel work already queued.

| JSON field | Default | Allowed range |
| --- | ---: | ---: |
| `reassemblyTimeoutSeconds` | 120 | 1–86400 |
| `maxReassemblyMessages` | 128 | 1–16384 |
| `maxFragmentsPerMessage` | 512 | 1–65536 |
| `maxConversationMessages` | 300 | 1–100000 |
| `maxCachedSentMessages` | 12 | 1–4096 |
| `maxDataTransfers` | 16 | 1–4096 |
| `maxDataReceipts` | 32 | 1–8192 |
| `maxDataAttempts` | 3 | 1–100 |
| `maxDataQueuedMiB` | 16 | 1–4096 |
| `dataTransferWindow` | 4 | 1–64 |
| `apiMaxMessagesPerSession` | 65536 | 1–1000000 |
| `apiRotateAfterBytes` | 1073741824 | positive byte count |
| `socketMaxBufferedMiB` | 4 | 1–1024 |
| `socketWindowChunks` | 4 | 1–1024 |
| `dataAckTimeoutSeconds` | 65 | 61–299 |
| `dataTransferTimeoutSeconds` | 240 | 1–86400 |
| `dataFragmentsPerTick` | 8 | 1–1024 |
| `sharingOfferTimeoutSeconds` | 60 | 1–300 |
| `maxPendingSharingOffers` | 4 | 1–1024 |

Time fields use seconds; `maxDataQueuedMiB` and `socketMaxBufferedMiB` use MiB. `maxDataAttempts`
includes the initial send. The overall transfer timeout includes queueing and may
end a transfer before all attempts are used. The ACK timeout stays above the
60-second optional-transfer assembly lifetime. Out-of-range values from JSON are
clamped when used, matching the settings screen bounds.

The overall transfer timeout can be extended to one day to allow longer queue
waits. Already encrypted data packets still expire after 300 seconds, so this does
not extend their validity or guarantee delivery after long retry delays. ACK waits
are capped at 299 seconds and sharing confirmations at 300 seconds to stay within
that packet lifetime. Larger queue/cache limits permit higher memory and disk use;
defaults remain unchanged.

Peers should choose compatible `maxFragmentsPerMessage` values for larger chat
messages. These settings adjust local resource limits and timing; cryptographic
sizes, protocol versions, Minecraft's chat length limit, and fixed wire-format
limits remain protocol constants.

## Build

```bash
gradle build
gradle -p neoforge build
```

If you prefer a wrapper, generate one with a local Gradle install:

```bash
gradle wrapper
./gradlew build
./gradlew -p neoforge build
```

## Releases

GitHub Actions builds the mod and publishes release artifacts automatically when a tag matching `v*` is pushed:

```bash
git tag v0.19.0
git push origin v0.19.0
```

The release workflow can also be triggered manually from the Actions tab. Manual builds are published under generated `snapshot-YYYYMMDD-HHMMSS` tags.

Release artifacts include:

- the mod JAR from `build/libs`
- a detached `.jar.sign` signature for each release JAR
- `public_key.pem` for signature verification

To verify a downloaded release JAR:

```bash
openssl dgst -verify public_key.pem -signature krypt04mcg-0.19.0.jar.sign krypt04mcg-0.19.0.jar
```

## License

Krypt04Mcg is licensed under the The Unlicense (`Unlicense`).

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

The encrypted cache is bounded by `maxConversationMessages` (300 entries by default) and is disabled by default. It can be enabled with the `enableConversationHistory` config option. With this option disabled, the GUI still displays up to `maxConversationMessages` live conversation entries in memory, without loading or saving conversation history on disk.

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
  Enable them through the Cloth Config screen or `config/krypt04mcg.json`. Both are disabled by default.
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

Optional-sharing validation and file cryptography run on a single background worker with no queued operations.
Incoming chunks received while that worker is busy are dropped; retry a transfer if the recipient does not receive a prompt.
Disconnecting, disabling sharing, or changing transport mode invalidates pending background results.
Expired assemblies and confirmation requests are cleaned up on client ticks, including on idle connections.

## Reliable Data API for other client mods (0.18.0)

Enable `enableDataApi` in Cloth Config or `config/krypt04mcg.json` on both clients (default: `false`). Set
`apiReceiver` to the default recipient's Minecraft player name. Each player must import the other's public key;
the existing Krypt04Mcg trust checks apply. This API always uses payload transport,
independently of `chatSendMode` and the file-sharing settings.

```java
import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.api.DataTransfer;

// Registration is allowed during client mod initialization.
Krypt04McgApi.registerReceiver("example:sync", (sender, bytes) -> {
    // sender is the verified player's name. Your mod interprets the opaque bytes.
    // Empty byte arrays are supported. Return normally to acknowledge delivery.
});

// Call send on the Minecraft client thread after joining a compatible server.
DataTransfer transfer = Krypt04McgApi.send("Alice", "example:sync", new byte[] {0, (byte) 0xff});
System.out.println(transfer.transferId()); // Stable UUID, also present in the result.
transfer.whenComplete(result -> {
    switch (result.status()) {
        case DELIVERED -> System.out.println("Remote receiver returned normally");
        case REJECTED -> System.out.println("Remote receiver missing, failed, or at capacity");
        case TIMEOUT -> System.out.println("No confirmation; delivery is uncertain");
        default -> System.out.println("Local failure: " + result.status());
    }
});

// Two-argument send uses apiReceiver and returns the same kind of handle.
Krypt04McgApi.send("example:sync", new byte[0]);
Krypt04McgApi.unregisterReceiver("example:sync");
```

The original `registerReceiver(channel, Consumer<byte[]>)` overload remains supported.
Registering either overload replaces the receiver for that exact channel. The sender
name comes from the verified signed envelope and must match the relay peer, ignoring
case. Application byte arrays are not parsed or validated by Krypt04Mcg.

`send` copies the input bytes before returning. Encryption, signatures, decryption,
verification and splitting run on one background worker. Receiver callbacks and
transfer completion run on the client thread. A `whenComplete` observer registered
after completion runs immediately on its caller; keep all callbacks short and never
block waiting for a transfer on the client thread. Observer exceptions do not alter
the transfer result. `completion()` exposes a read-only `CompletionStage<TransferResult>`
for standard Java chaining; completing or cancelling its converted future does not
complete or cancel the underlying transfer.

| Result | Meaning |
| --- | --- |
| `DELIVERED` | Authenticated ACK from the intended peer, after its receiver returned normally. |
| `REJECTED` | Authenticated NACK: unknown channel, receiver exception, or full deduplication cache. |
| `TIMEOUT` | Confirmation did not arrive within the retry/deadline budget. The peer may have processed the data. |
| `BACKPRESSURE` | Local queue count/byte budget or per-message size limit exceeded. Nothing was queued. |
| `DISABLED` | Local API is disabled or was disabled while a transfer was pending. |
| `DISCONNECTED` | Relay unavailable, disconnected, or transport closed. |
| `FAILED` | Key missing/changed/distrusted, encryption failure, or local payload send failure. |

Null arguments, calling before mod initialization, or sending off the client thread
remain programming errors that throw. Queue saturation returns a completed handle
instead of throwing `already sending`. No acknowledgements are sent for unauthenticated,
malformed or expired packets, or while the receiving API is disabled.

### Limits, retries and delivery semantics

- Up to 16 pending transfers and 16 MiB of queued input (bytes plus channel string
  accounting). One message may contain at most 10 MiB; the existing 16 MiB plaintext
  envelope and 2048-fragment transport bounds also apply. These are resource limits,
  not application data-format restrictions.
- Complete envelopes are emitted in order, but up to `dataTransferWindow` transfers
  may concurrently wait for ACK. At most eight 12,000-character fragments are sent
  per client tick. Receipts have priority between complete envelopes; fragments of
  different envelopes are not interleaved. ACK/NACK completion is matched by UUID
  and may arrive out of order.
- Wait 65 seconds for an ACK after the final fragment, then retry the whole signed
  packet with a fresh assembly ID. The UUID and encrypted packet stay unchanged.
  There are at most three attempts and a four-minute deadline from enqueue, including
  queue time and encryption. The wait exceeds the assembler's 60-second expiry so a
  missing fragment cannot permanently block a retry.
- Receive assembly, the verification queue and receipt queue are bounded. Excess
  incoming work is dropped and may be retried by the sender. ACK and NACK use the
  same encrypted, signed KEM envelope as data and are bound to the intended peer
  and transfer UUID. Receipts never acknowledge other receipts.
- Up to 1024 received outcomes are retained until the signed packet expires. A
  duplicate transfer resends its original ACK/NACK without running the callback
  again. Full outcome storage rejects new messages rather than evicting unexpired
  outcomes. Disabling clears pending work but keeps outcomes; disconnecting clears
  connection state, and stale background results cannot send or deliver afterward.
- This is bounded retry with deduplication within a connection, not durable exactly-once
  delivery across reconnects or restarts. `DELIVERED` does not mean saved to disk.
  A throwing receiver may already have partial side effects; it gets NACK and is not
  called again for that transfer. Applications needing durable transactions should
  implement their own IDs and storage. Do not blindly treat `TIMEOUT` as non-delivery.

### Compatibility and relay support

This pipeline change does not alter the DataTransfer or stream wire formats and does
not change the public `KryptSocket`, `KryptSession`, stream, or tunnel entry points.
New configuration and session-record fields are additive. Older encrypted session
records load with zero API usage and a conservative replay bitmap that continues to
reject every sequence below their persisted receive counter.

Both endpoints need 0.18.0 or newer for reliable sending. New clients still receive
legacy v1 fire-and-forget data without receipts; new v2 messages sent to older clients
time out. Changing `send` from `void` to `DataTransfer` preserves source calls that
ignore the result, but changes the JVM method signature: **recompile dependent mods**
and require Krypt04Mcg >= 0.18.0. No separate API JAR is required.

The server relay still forwards the optional `krypt04mcg:data` channel. No relay
protocol change is needed if it already forwards this channel opaquely. Wire fields
remain `writeUtf(peer, 16)`, `writeUtf(fragment, 12100)`, `writeVarInt(1)`, using
Minecraft UTF-8/VarInt encoding. Client-to-server `peer` is the recipient; the relay
must replace it with the authenticated sender's name on server-to-client packets.
Only forward to the named online recipient subscribed to the channel.

The encrypted envelope domain is `krypt04mcg:data:v2`, with `transferId` (canonical
UUID), `kind` (`DATA`, `ACK`, `NACK`), and DATA-only `channel` and Base64 `data` fields.
The relay does not parse these fields or decrypt contents. Application channel names
are independent of the Minecraft payload channel. There is no chat fallback.

The static `send` API continues
to use signed KEM cryptography. The optional Session API below avoids KEM on subsequent data messages.

## Stream API

`KryptSocket` adds an ordered, full-duplex byte stream on top of the authenticated
Session API. It uses the existing `krypt04mcg:data` Minecraft Custom Payload and
therefore requires no Relay update beyond support for that payload.

```java
import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.api.KryptSocket;

// Register during client initialization. The callback runs on the client thread.
Krypt04McgApi.registerSocketReceiver("mymod:test", socket -> {
    // Hand the socket to a worker before performing blocking reads.
});

try (KryptSocket socket = Krypt04McgApi.connect("Alice", "mymod:test")) {
    socket.getOutputStream().write(bytes); // call writes on the client thread
    // InputStream.read(...) is blocking; call it from a worker, never the client thread.
}
```

The stream wire format is internal and versioned as `krypt04mcg:stream:v2`. Each frame
carries a random stream UUID and is one of `OPEN`, `DATA`, `CLOSE`, or `RESET`. DATA
frames contain a monotonic 64-bit sequence and at most 128 KiB. `socketWindowChunks` controls the number
of in-flight chunks (default 4). `socketMaxBufferedMiB` limits each socket's queued
output and unread input separately (default 4 MiB each); in-flight output is separate
from the queued output limit. Both settings apply to outgoing and accepted sockets.
Saving in Cloth Config applies the limits to subsequent writes, received DATA, and
window checks on existing sockets; lowering them does not discard buffered data or
cancel in-flight chunks. A write exceeding the available buffer limit throws
`IOException` instead of blocking the client thread. Frames are themselves sent with
the reliable Session API, so encryption, peer authentication, retries, Relay routing,
and transport ACK/NACK remain unchanged. v2 adds no second stream ACK: a DATA
DataTransfer reaching `DELIVERED` confirms that chunk. Completions may arrive out of
order, but only a bounded contiguous prefix advances the per-stream send window; any
non-delivery result resets the socket. The receiver accepts DATA within a bounded
`socketWindowChunks` reorder window, delivers only contiguous sequences, and ignores
duplicate stream sequences. DATA beyond that window, malformed frames, and receive
buffer overflow reset the stream. Session sequence and replay checks remain enabled.

`close()` drains queued DATA and waits for every submitted DATA completion before sending CLOSE. End-of-stream is
reported as `-1` after the peer CLOSE. Closing only the returned `InputStream` discards
future inbound bytes and wakes blocked readers with `IOException`, but leaves the output
direction usable and does not send RESET. Register at most one socket receiver per
logical channel; a new registration replaces the previous listener.

The default protocol-rate calculation and remaining client/Relay bottlenecks are
documented in [PERFORMANCE.md](PERFORMANCE.md).

## Session API (0.19.0)

`connect` reuses a valid authenticated `/exchange` session or starts that same exchange
automatically over the reliable `krypt04mcg:data` transport. Both endpoints must run
0.19.0 or newer and enable `enableDataApi`. The relay wire format is unchanged: an
existing transparent relay does not need new channels or knowledge of session secrets.

```java
import dev.krypt04mcg.api.KryptSession;
import dev.krypt04mcg.api.Krypt04McgApi;

KryptSession session = Krypt04McgApi.connect("Alice");
// This is safe before readiness; it uses the existing bounded transfer queue.
session.send("mymod:data", bytes).whenComplete(result -> {
    System.out.println(result.status()); // Same reliable transfer results as static send.
});

session.ready().whenComplete((connected, error) -> {
    if (error != null) {
        System.err.println("Session establishment failed: " + error.getMessage());
    } else {
        System.out.println(connected.peer() + ": " + connected.sessionId());
    }
});
// Later, when this integration no longer needs the handle:
// session.close();
```

- Call `connect`, `session.send` and `session.close` on the client thread. Connection
  establishment returns immediately with a handle. `ready()` is a read-only
  `CompletionStage<KryptSession>` and fails on handshake failure, timeout, disable
  or disconnect. Do not block the client thread waiting for it.
- Existing `registerReceiver(channel, (sender, bytes) -> ...)` handlers receive both
  signed KEM and session messages. For session messages, the sender is authenticated
  by AEAD under the identity-bound handshake secret, not by a new signature per message.
- `peer()`, `isReady()` and `sessionId()` expose no secret. Readiness describes successful
  local setup, not a live connection check; every send rechecks trust, key identity,
  expiry and session epoch. Both peers retain the same master session ID and secret.
- At most 16 peer handles are retained. Repeated `connect` for the same valid peer
  returns its current handle. Establishment and data share the 16-transfer/16-MiB
  queue and four-minute deadlines; handshake responses have priority to prevent
  queued data from blocking establishment. Failures never fall back to unsigned data.
- `close()` invalidates the local handle and fails its queued sends. It does not erase
  the stored chat session or send a stream-close frame. Closing immediately after
  calling `send` can cancel it, so retain the handle until its transfers finish.
- Session TTL remains shared, while API DATA uses independent
  `apiMaxMessagesPerSession` and `apiRotateAfterBytes` counters. Bulk streams therefore
  do not consume the ordinary chat `maxMessagesPerSession`/`rotateAfterBytes` budget;
  receipts consume neither budget, so a final message can still be acknowledged. An exhausted,
  replaced or mismatched epoch fails closed. Call `connect` again to obtain a fresh
  epoch; existing handles never silently switch keys for queued/retried data.
- Disable/disconnect invalidates handles and pending work. A subsequent connection
  may reuse an unexpired persisted session. Sessions written by versions before
  0.19.0 lack local-key binding, so the first `connect` refreshes them through exchange.
  The static v0.18 reliable send API remains compatible and independent.

### Session authentication and sequence handling

Handshake control messages use reliable signed KEM envelopes (`EXCHANGE` in the
existing v2 Data API envelope), containing the existing signed `SESSION_EXCHANGE`
packet. Ephemeral key generation and outer envelope encryption run on the background
worker; completing the small handshake and committing session state use the client
thread. Retries resend the same handshake packet and do not regenerate the session
secret. Simultaneous connections use the existing deterministic exchange tie-break.

After setup, data and ACK/NACK use protocol-v4 `SESSION_MESSAGE` packets with session
ID and authenticated sequence metadata. The API derives a separate 32-byte key with
HKDF-SHA256, using the master secret, session ID as salt, and the label
`krypt04mcg data session v1`. Chat continues using its original key derivation.
A data ciphertext cannot be replayed into chat or vice versa. The encrypted API
plaintext domain is `krypt04mcg:data:session:v1`.

API counters are stored atomically alongside the encrypted session record, separately
from chat counters. DATA uses even wire sequences; receipts use odd sequences, with
independent persisted 64-entry replay/reorder windows. Gaps and bounded reordering are
accepted because encryption failure, pipelining, delayed ACKs, and retry may reorder
arrival; duplicates and packets older than the window remain rejected. Receipts can
overtake queued data without blocking it. Counters are reserved before encryption and never reused; retrying a transfer
reuses its original authenticated packet and sequence. Cached duplicates only resend
the original result. After a restart without the outcome cache, persisted receive
counters reject old data instead of calling the receiver again. This still is not a
durable exactly-once transaction or proof of application persistence.

Stream/socket APIs remain deferred. Files retain their existing signed KEM transfer
format; this release adds shared sessions for the Data API without changing file or
chat message formats.
