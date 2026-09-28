# Tunnel transport and verification

## Root cause of the old stalls

The old path was KryptSocket -> KryptSession.send -> DataTransferService ->
OptionalTransferAssembler -> DataPayload. A 128 KiB socket chunk was base64-encoded
inside JSON, encrypted, base64-encoded again, and split into about 20 payloads.
Both socket completion windows and transfer ACK/retry windows limited progress.
The five-minute transfer deduplication cache stopped admitting new transfers at
1024 entries and returned NACK. Any failed DATA transfer closed/reset the socket.
Full output buffers threw "KryptSocket backpressure"; full receive buffers reset
streams. Per-envelope durable session updates added disk work to that hot path.

## New data path

Application I/O worker -> bounded KryptSocket queue -> single tunnel encryption
worker -> one 8 KiB DATA frame per TunnelPayload -> Minecraft TCP/relay ->
Netty FlowControlHandler -> tunnel decryption worker -> bounded socket input ->
application reader.

OPEN, DATA, CLOSE and RESET all use this path. There are no DATA receipts, retries,
waitingAck entries, sliding windows, secondary fragments, or per-tick send quotas.
The existing DataTransferService still handles ordinary messages and session
handshakes. File sharing keeps its existing transport.

The frame queue is bounded per stream by socketMaxBufferedMiB, plus one worker-held
frame. The shared send queue holds at most 32 frames. The inbound handler processes
one payload at a time; FlowControlHandler retains only the already-decoded read
batch and requests more TCP input after processing makes progress. The handler is
before vanilla bundle assembly, so bundled custom payloads also bypass main-thread
dispatch. Slow streams share TCP head-of-line blocking with other streams and game
traffic. A relay must implement bounded forwarding with real transport backpressure;
a plugin that queues indefinitely or drops messages cannot provide these guarantees.

Each OPEN reserves a durable, encrypted stream lease using an interprocess lock,
atomic replacement and forced file writes. Stream UUID, lease, epoch and direction
separate the AEAD keys. OPEN replay state is persisted before delivery; DATA uses
strict in-memory per-direction counters without writing session or counter files.
Reads of trust/key/session state still occur on workers before frames, so disk read
and AEAD/HKDF costs remain possible bottlenecks. Old message API count/byte rotation
limits do not close active tunnel streams; trust revocation, epoch changes and the
configured session TTL still apply.

## Regression tests

Run:

    ./gradlew test
    ./gradlew -p neoforge build

The shared integration harness uses real authenticated session exchange, both
multiplexers, AEAD and ordered links with two-payload bounded queues. It verifies:

- Continuous 100 MiB with 12,800 DATA frames, exact byte equality, no reverse ACK
  frames, no retransmission, no unexpected closure, and ten progress intervals.
- An 8 MiB transfer to a slow receiver, including an initial blocked phase and
  resumed progress without RESET.
- Three streams sending 4 MiB concurrently in each direction (24 MiB total).
- Ordinary reliable Data API traffic alongside tunnel traffic.
- File contents and mtimes stay unchanged during DATA traffic.
- Tamper/replay rejection, both AEADs, stream/peer/epoch/counter binding,
  durable counter restart and concurrent reservations.
- Interrupted/disconnected I/O, local flush completion, close/EOF order, and
  explicit main-thread I/O guards.
- Real Netty EmbeddedChannel/FlowControlHandler demand: a blocked consumer stops
  payload delivery while event-loop tasks still run; ordinary packets pass in order.

On this Windows host, the first 100 MiB run took 18.38 seconds. Its ten 10 MiB
intervals were 2.55, 2.02, 1.99, 1.74, 1.72, 1.72, 1.70, 1.66, 1.63 and 1.65 seconds.
These are in-process correctness/regression measurements, not a Minecraft-server
bandwidth promise. The server relay is outside this repository; real server/proxy
rate limits, TCP behavior, mixin installation in a launched game and relay support
for the new krypt04mcg:tunnel channel require deployment testing.

Final verification record: Fabric full build completed with 287 tests, zero failures,
and one existing Windows symlink-permission skip; NeoForge build and seven tests
passed. The subsequent trust-revocation cleanup, disconnect-race guards, and
late channel-advertisement handling still need a final build/test rerun. The final
rerun request was denied, so those last edits have only been reviewed statically.
