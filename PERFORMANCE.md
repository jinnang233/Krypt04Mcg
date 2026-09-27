# API tunnel throughput budget

The stream and reliable-transfer windows remove round-trip stop-and-wait from the
steady-state path, but they do not remove authentication, encryption, receipts, or
resource bounds.

## Protocol ceiling

The default sender emits at most `8 fragments/tick * 20 ticks/second = 160`
`DataPayload` fragments per second. Each fragment carries at most 12,000 characters
(the Minecraft codec accepts 12,100 including framing metadata), so the outer encoded
ceiling is 1,920,000 characters/second.

A full stream DATA frame contains 128 KiB plus 30 bytes of stream framing. Application
bytes are Base64URL-encoded inside JSON and the encrypted packet is Base64URL-encoded
again before fragmentation. The dominant expansion is therefore approximately
`4/3 * 4/3 = 16/9`. A 128 KiB stream chunk occupies about 233–234 KiB of fragment text,
or 20 fragments. At 160 fragments/second this gives roughly eight stream chunks per
second: about 1 MiB/s of one-way application data before headers and scheduling costs.

Each DATA chunk produces one authenticated ACK/NACK. A session receipt normally fits
in one reverse-direction fragment. Receipts therefore add crypto, persistence, and
client-thread work, but no longer consume a second stream-level reliable round trip.

## Remaining limits

- `dataFragmentsPerTick` and the 20 TPS client tick are the first explicit wire-rate
  limit. Raising it increases burst load on Minecraft and the Relay/Spigot plugin.
- `OptionalTransferAssembler.CHUNK` is 12,000 characters and `DataPayload` is capped at
  12,100 UTF characters, so a 128 KiB chunk necessarily spans about 20 payloads.
- Base64URL is applied both to application bytes in the API envelope and to the packet,
  accounting for most protocol expansion.
- Session DATA uses AEAD rather than per-message KEM/signature after the handshake.
  Nevertheless, the single `SharingWorker` serializes envelope encrypt/decrypt work,
  and session counter persistence performs encrypted file updates.
- Fabric/NeoForge enqueue received payload handling onto the client thread. A busy
  client, slow disk, or long callback delays fragment assembly and receipt generation.
- Relay/Spigot forwarding policy is outside this repository. Packet-per-tick limits,
  plugin-message queues, proxy hops, or server-side throttling can reduce the ceiling
  substantially and must be measured separately.
- `KryptSocket` reads use a worker by contract. Blocking reads or large writes on the
  Minecraft client thread can still starve ticks even though queueing itself is bounded.

The encrypted in-memory integration harness is not a network benchmark: it deliberately
ticks faster than 20 TPS. On the test host it transferred 4, 16, and 64 MiB in roughly
2.6, 9.5, and 35.6 seconds. Its purpose is to prove pipeline progress, byte equality,
rotation survival, and cleanup. If a real server remains near 15 KiB/s, inspect
`pipelineStats()`: a full `waitingAck` window points to receipt/Relay latency, sustained
`sending` with few fragments points to tick or forwarding limits, and sustained
`preparing` points to crypto or session-store latency.
