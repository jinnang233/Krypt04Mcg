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
- Configurable CMCE, HQC, NTRU Prime and ML-KEM key parameter sets, with X25519/X448 hybrid options.
- Bouncy Castle native composite ML-DSA signatures with EdDSA, ECDSA or RSA.
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
- Fabric API `0.162.0+26.3`
- Loom `1.18.2`
- Gradle `9.8.0`
- ModDevGradle `2.0.148`
- JUnit `6.1.3`
- NeoForge `26.3.0.52-beta` (separate client build)
- Bouncy Castle `1.86`
- Java `25`

Dependency updates use the latest published stable versions compatible with Minecraft 26.3; snapshot, alpha, beta and release-candidate versions are excluded except for NeoForge.

The NeoForge build shares the protocol, cryptography, and storage code with Fabric. It requires no server installation for chat transport. Custom payload and public-key sharing still require a server relay that advertises the corresponding channels.

NeoForge's optional Cloth Config integration uses `26.3.159` for Minecraft 26.3 and detects its NeoForge mod ID, `cloth_config`. Install Cloth Config separately to enable saved settings and the config screen. The mod starts with default settings when Cloth Config is absent.

## Build

Use an installed Gradle 9.8.0 for these commands. CI installs the same stable version;
Gradle Wrapper files are managed separately.

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

The long-term KEM, ephemeral KEM, signature and AEAD configuration fields use dropdown menus on both Fabric and NeoForge.

The KEM and signature selections only apply when no local key exists or when a key is explicitly regenerated. Changing the configuration never rewrites an existing key. Encryption, signing, verification, and decryption resolve algorithms from key records and packet algorithm identifiers rather than assuming the current configuration.

Supported key selections are the eight ISO/IEC 18033-2 CMCE parameter sets already exposed by this mod
(`mceliece460896`, `mceliece6688128`, `mceliece6960119`, and `mceliece8192128`, each with its `f` variant),
HQC-128/192/256, all six parameter sets for each of NTRULPRIME and SNTRUPRIME,
ML-KEM-512/768/1024, Falcon-512/1024,
ML-DSA-44/65/87, all 24 SLH-DSA variants (the 12 SHA2/SHAKE parameter sets in both pure and pre-hash forms),
all three SQIsign parameter sets (`SQIsign-lvl1`, `SQIsign-lvl3`, and `SQIsign-lvl5`),
and all 44 SNOVA variants. SNOVA includes the base parameter sets `24-5-4`, `24-5-5`, `25-8-3`,
`29-6-5`, `37-8-4`, `37-17-2`, `49-11-3`, `56-25-2`, `60-10-4`, `66-15-3`, and `75-33-2`,
each with `SSK`, `ESK`, `SHAKE-SSK`, and `SHAKE-ESK` variants (for example, `SNOVA-24-5-4-SSK`).
The long-term defaults are `ML-KEM-768+X25519`, `MLDSA65-Ed25519-SHA512`, and `AES-256-GCM`. The independently configurable ephemeral KEM used only by `/k04m exchange` and `/k04m etell` sessions also defaults to `ML-KEM-768+X25519`.

Version 0.25.0 adds 52 hybrid KEM selections: every supported KEM parameter set can be paired
with either `X25519` or `X448` (for example, `HQC/hqc192+X448`). These selections are available
for both long-term keys and the independently configured ephemeral handshake key.
`ML-KEM-768+X25519` uses BC's native `MLKEM768-X25519-SHA3-256` composite KEM;
`ML-KEM-1024+X448` uses BC's native `MLKEM1024-X448-SHA3-256` composite KEM.
All other pairings use BC's existing KEM and X25519/X448 implementations, combined by BC's
HKDF-SHA256 over the PQ secret followed by the classical secret. The HKDF context binds
a versioned domain label, the exact suite identifier, both encapsulations and both recipient public keys.
No classical curve or post-quantum primitive is implemented by this mod. Invalid or missing
components fail the operation; hybrid selections never fall back to a single component.
The custom combinations are a mod-specific format, not X-Wing or a standard composite KEM.

The signature selector also offers all 18 BC native composite signature suites: ML-DSA-44
with Ed25519, ECDSA P-256 or RSA-2048; ML-DSA-65 with Ed25519, ECDSA P-256/P-384/brainpoolP256r1
or RSA-3072/4096; and ML-DSA-87 with Ed448, ECDSA P-384/P-521/brainpoolP384r1 or RSA-3072/4096.
RSA choices include the PKCS#1 v1.5 and PSS variants exposed by BC (ML-DSA-87 uses PSS only).
Signing, combination, key encoding and verification are delegated to BC; verification requires both signatures.
Example selections are `MLDSA44-Ed25519-SHA512` and `MLDSA87-Ed448-SHAKE256`.

Version 0.26.0 adds all 97 parameter selections exposed by BC 1.86 for these additional signatures:

| Family | Parameter selections |
| --- | ---: |
| MAYO | 4 (`MAYO-1/2/3/5`) |
| HAETAE | 3 (`HAETAE-2/3/5`) |
| UOV | 12 (IS/IP/III/V, each in base, PKC and PKC-SKC forms) |
| QR-UOV | 12 |
| AIMer | 6 (128/192/256, each with f/s variants) |
| FAEST | 12 (128/192/256, f/s, ordinary and EM variants) |
| MQOM | 36 (MQOM2 CAT1/3/5, GF2/GF16/GF256, FAST/SHORT, R3/R5) |
| SDitH | 12 (HYPERCUBE/THRESHOLD, CAT1/3/5, GF256/P251) |

Each selection also has `+Ed25519` and `+Ed448` hybrid variants, adding 194 hybrid choices.
Examples include `MAYO-1+Ed25519`, `HAETAE-3+Ed448`, `QR-UOV/qruov1q127L3v156m54+Ed25519`
and `SDITH-THRESHOLD-CAT5-P251+Ed448`. BC provides the PQ and classical key generation,
key decoding, signing and verification. These new pairings use a mod-specific versioned format;
they are not BC's native ML-DSA composite suites and are not a standardized composite signature format.
Both components sign the same length-framed transcript containing a versioned domain label,
the exact suite identifier, the SHA-512 hash of both public keys and the SHA-512 hash of the message.
Hashing is performed by BC. Verification requires both signatures; incomplete signatures,
malformed framing and trailing bytes are rejected, with no fallback to a single component.
The existing BC native ML-DSA composite signatures and the hybrid defaults remain unchanged.

The new signature families are experimental, non-standardized selections. Large UOV public keys
are supported by local import/export and the optional public-key sharing channel, whose bounded
maximum is now 512 chunks (about 6 MB of JSON). This accommodates the largest UOV public key
alongside the largest supported CMCE public key. Chat packet and fragment limits remain in force.
Both peers need version 0.26.0 or newer for the new signature suites and larger public-key transfers.

Existing keys and explicit saved selections stay unchanged; new and missing selections default to the hybrid suites above. To use a long-term hybrid KEM or hybrid signature,
select it in the configuration, explicitly regenerate your keys and exchange the new public keys
with your contacts. An ephemeral hybrid selection takes effect on the next exchange without
regenerating long-term keys. Both peers need version 0.25.0 or newer to use these suites;
existing non-hybrid suites remain supported and the packet protocol version is unchanged.

Bouncy Castle 1.86 removes the round-3 CMCE implementation and the non-standardised
`CMCE/mceliece348864` and `CMCE/mceliece348864f` selections. Saved configurations using either removed
selection fall back to `ML-KEM-768`. Existing round-3 CMCE keys cannot be decoded by 1.86, even for
parameter sizes still supported by the ISO implementation. Back up the account storage before upgrading;
CMCE users need to replace their local keys and exchange fresh public keys with their contacts.
Existing ML-KEM keys remain usable.

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

`/k04m exchange` is a signed two-message handshake using the dedicated `SESSION_EXCHANGE` packet type. The initiator creates an in-memory one-time KEM key pair (`ML-KEM-768+X25519` by default); the responder encrypts fresh session material only to that temporary public key and binds both identities, UUIDs, both fingerprint pairs, the session ID, and the request message ID into the exchange transcript. The initiator destroys the temporary private key after accepting the response or after a short timeout. Consequently, later compromise of either long-term KEM private key does not decrypt a recorded exchange response.

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

The mod remains client-only and can join vanilla servers. Basic chat operations keep their
existing behavior. Payload sharing is optional: a server without the corresponding plugin
simply has no API/file channel transport. No server mod is required or included.

`CHAT` and `SERVER_COMMAND` send fragments on the client thread at intervals of at least
1 second (`max(sendDelayMs, 1000)`), matching vanilla's normal 20 TPS spam budget.
`CUSTOM_PAYLOAD` uses `sendDelayMs` directly. Disconnecting or changing servers cancels
queued chat fragments. On vanilla, import the other player's public keys locally and use
`CHAT` for encrypted messages; API streams and optional payload sharing need a relay.

Public-key sharing is unchanged and uses `krypt04mcg:public_key` in `CUSTOM_PAYLOAD` mode.
`/k04m-share key [player]` sends a public-key offer, which is imported only after acceptance.

File sharing now uses the encrypted stream API described below. `/k04m-share file <player> <path>`
requires both players' imported public keys and `CUSTOM_PAYLOAD` mode. Sending and receiving
are independently disabled by default (`enableFileSending`, `enableFileReceiving`). The file
limit remains **10 MiB**. Filename and content are encrypted and authenticated. A file offer
appears only after the complete stream and authenticated EOF have been received. Files are
saved only after explicit acceptance and a fresh identity/trust check, under `received-files`
with sanitized names and a random prefix. Files are never opened or executed automatically.
Up to four offers, including at most one file, may await consent for 60 seconds.

`/k04m-share disable-files` or `permanentlyDisableFileSharing=true` persists the existing
account-level file-sharing lock. Disabling sharing, disconnecting, or switching transport
mode cancels active file work. File sending queues at most four 16 KiB portions per tick;
these are byte-stream writes, with no fragment IDs, reassembly or data acknowledgements.
The existing key-offer UI, file-offer consent UI, and translations remain in use.

## Raw encrypted channel API

This is a breaking replacement of the old reliable transfer API. `DataTransfer`,
`TransferResult`, DATA/ACK/NACK envelopes, completion receipts, retransmissions and the old
`krypt04mcg:data` / `krypt04mcg:file_share` payloads have been removed.

Enable `enableDataApi` to use the public API. `apiReceiver` remains the default peer for
convenience sends. File sharing uses its own enable switches and does not require enabling
the public data API. A compatible Spigot relay plugin will be implemented separately;
the client transport will remain unavailable until the server advertises its channels.
Unavailable transport fails a requested API operation without preventing login or chat.

`apiChannelCount` pre-registers **1..256** Minecraft data channels, default **16**. Set it
in the Cloth Config configuration file; without Cloth Config, set the same field in
`config/krypt04mcg-stream.json`. Changing the count requires restarting the client.
The channel namespace is dedicated to this transport:

| Minecraft channel | Payload |
| --- | --- |
| `krypt04mcg_stream:control` | Allocation, signed exchange, ready, authenticated EOF/reset, relay abort |
| `krypt04mcg_stream:data/0` … `data/(n-1)` | Exactly XChaCha20-Poly1305 ciphertext plus its 16-byte authentication tag |

Data channels have no application protocol header, sender/recipient, stream ID, sequence,
nonce, fragment metadata, inner length field, Base64, JSON or algorithm selector. Minecraft
supplies ordered reliable delivery and the record boundaries. Each record protects up to
16 KiB of plaintext; the application sees an InputStream/OutputStream regardless of record
boundaries. Buffer exhaustion fails the stream instead of dropping authenticated bytes.

```java
import dev.krypt04mcg.api.Krypt04McgApi;
import dev.krypt04mcg.api.KryptSocket;

// Registration and opening run on the Minecraft client thread.
Krypt04McgApi.registerSocketReceiver("example:stream", socket -> {
    // Read on your background executor; never block the Minecraft client thread.
    executor.execute(() -> {
        try {
            byte[] bytes = socket.getInputStream().readAllBytes();
            // Process authenticated bytes; impose your application's own size limit.
        } catch (java.io.IOException failure) {
            // Reset, authentication error, truncated stream, timeout or disconnect.
        }
    });
    socket.close(); // Half-close output; input remains readable.
});

KryptSocket socket = Krypt04McgApi.connect("Bob", "example:stream");
int offset = 0; // Keep socket, bytes and offset as sender state across ticks.

// Run this step on each client tick, with a single producer for this socket.
// Handle IOException or socket.isFailed() by stopping this sender.
int count = Math.min(socket.writableBytes(), bytes.length - offset);
if (count > 0) {
    socket.getOutputStream().write(bytes, offset, count);
    offset += count;
}
if (offset == bytes.length) socket.close(); // Queued bytes precede authenticated EOF.
// Otherwise return to the client loop and resume next tick; never spin on capacity.
```

Streams may be written before exchange/allocation completes. Each direction buffers at
most 1 MiB; `writableBytes()` lets producers pace writes, and writes beyond capacity throw
IOException without partially accepting the write. Reads may block; writes only enqueue
copied bytes and are thread-safe. Capacity checks do not reserve space: multiple producers
must serialize the check and write together on the socket monitor. Opening connections and
control/listener callbacks run on the Minecraft client thread. `close()` half-closes output. Closing input cancels the
stream. Idle/allocation/exchange timeout is 60 seconds. Concurrent streams cannot exceed
the configured channel pool. Scheduling rotates between active streams.

The convenience `send(player, channel, bytes)` returns void and writes one stream followed
by EOF (at most 1 MiB). `registerReceiver(channel, (sender, bytes) -> ...)` receives stream
portions on the client thread; each callback is **not** a complete application message.
Applications needing their own messages should use socket streams and define their own
content format. No API result claims remote delivery or persistence.

`connect(player)` returns a KryptSession handle with `ready()` for exchange readiness,
`isReady()` and `sessionId()`. This readiness is local session establishment, not a data
completion receipt. Its `send(channel, bytes)` has the same convenience-send semantics.
Session secrets are never exposed by these public handles.

All stream data encryption calls BouncyCastle's
[`org.bouncycastle.crypto.modes.XChaCha20Poly1305`](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/modes/XChaCha20Poly1305.html) directly; no cipher or HChaCha implementation
is maintained in the mod. Keys are derived with BouncyCastle HKDF-SHA256 and separated by
session, stream ID, channel slot, application channel, direction and purpose. The 24-byte
nonce contains the stream ID and implicit direction-local record counter; only ciphertext
and the tag are transmitted. Authentication is checked before plaintext is released.
Replay, reordering, reflection and cross-channel substitution fail authentication.
Self-connections are rejected because the endpoints must have distinct directional keys.

Exchange reuses the existing signed KEM exchange machinery on the control channel, with
separate storage under `stream-api` to keep chat sessions independent. Exchange packets
must fit in one control payload (30,000-byte body); unsupported oversized exchange material
fails rather than introducing fragmentation. Exchange's envelope cipher belongs to that
existing handshake format; data channels always use XChaCha20-Poly1305, independently of
the chat AEAD setting. Authenticated OPEN counters persist in the separate session store
for replay protection. Session TTL and rotation limits are checked; active streams validate
their identity and session epoch. Stream keys are erased when their slot is released.

EOF is an authenticated control message containing the final record count. A dropped
record, unauthenticated close, connection loss or failed tag cannot become successful EOF.
READY is allocation readiness only; there are no per-data ACKs or completion receipts.

## Contract for the future Spigot relay

Only the control channel is decoded by the relay. The client control codec defines
`EXCHANGE`, `OPEN`, `ASSIGNED`, `READY`, `END`, `RESET`, and `ABORT`. The control payload contains
kind, peer, stream UUID, slot, application channel, session ID, sequence and bounded body.
The relay obtains the source player from the authenticated Minecraft connection, never
from a claimed source field. It rewrites `peer` to the authenticated source when forwarding
control messages. Exchange bodies are signed encrypted packets; other client controls
carry a 32-byte authentication tag. ASSIGNED and ABORT are relay lifecycle notifications.
ABORT is always a failure, never EOF.

OPEN requests slot -1. The relay picks a free slot supported by both clients, sends
ASSIGNED with the chosen slot to the opener, then forwards OPEN on that slot to the peer.
The peer verifies OPEN, reserves its persisted anti-replay counter, installs the stream,
and sends authenticated READY binding the chosen slot. Both ends then map that slot to
one stream in an array. The relay should likewise maintain an array of source/target pairs
and forward the exact raw payload on the same data channel without inspecting or wrapping
its bytes. Refuse data from anyone outside the assigned pair, before READY, or after that
sender's END. Release a slot after both directional ENDs, RESET, disconnect or timeout.
Keep control and data forwarding ordered. Bound allocations and traffic per source.
No server implementation is shipped in this mod.
