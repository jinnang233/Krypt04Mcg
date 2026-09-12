# Security Code Review (2026-09-12)

This review focused on `CryptoService`, `PacketCodec`, fragment reception, session handshakes, and sequence handling. It also examined the main paths for key import, trust bindings, and local sensitive-file storage. The issues below were fixed without changing the wire format of normal messages.

## Confirmed and fixed issues

### 1. [P2] Key labels were not bound to actual algorithm parameters

Location: `CryptoService.validatePublicRecord` / `validatePrivateRecord`.

The original implementation decoded keys using the algorithm family's generic `KeyFactory`, then generated a normalized record using the algorithm label from the input record. Experiments confirmed that an ML-KEM-512 public key labeled as ML-KEM-1024, or an ML-DSA-44 public key labeled as ML-DSA-87, still passed import validation. Relabeling both keys in a local key pair also bypassed the original key-pair consistency check. This allowed displayed algorithms and handshake declarations to differ from the parameters actually used; it did not demonstrate signature forgery or a break of these algorithms.

Fix: inspect the decoded key's parameter object and verify its type and name for long-term public keys, private keys, and ephemeral handshake public keys. This covers the seven key families supported by the project. Bouncy Castle key interfaces expose the actual parameters, for example through [MLKEMKey.getParameterSpec](https://downloads.bouncycastle.org/java/docs/bcprov-jdk15to18-javadoc/org/bouncycastle/jcajce/interfaces/MLKEMKey.html).

Regression coverage: `KeyParameterBindingTest` verifies rejection of mislabeled long-term public keys, ephemeral public keys, and local keys. Both new tests failed against the original implementation and passed after the fix.

Compatibility: mislabeled key records that were previously accepted are now rejected. Verify the original key and its actual parameters; changing a label alone cannot increase its security level.

### 2. [P2] Permissive protocol string decoding accepted noncanonical encodings

Location: `PacketCodec.readString`.

The original implementation used `new String(..., UTF_8)`, which replaces malformed UTF-8 with U+FFFD. Because AAD and signature inputs are reconstructed from decoded strings, different raw byte sequences could produce the same authenticated input. This was a protocol encoding ambiguity; it was not demonstrated to alter ordinary ASCII player names or bypass AEAD.

Fix: use a strict UTF-8 decoder and reject malformed encodings immediately. Also align encoder and decoder limits for strings and byte fields with 32-bit lengths, preventing the local encoder from producing data that the receiver must reject.

Regression coverage: `PacketCodecTest` covers malformed UTF-8, oversized strings, and oversized byte fields. The original permissive decoder failed the new rejection test.

### 3. [P2] Duplicate fragments could repeatedly refresh cache expiry

Location: `FragmentReassembler.accept`.

The original implementation updated `lastTouched` even when receiving an identical duplicate fragment. Repeated delivery could keep incomplete messages in the cache indefinitely and affect eviction of legitimate messages. The message count was already bounded, so this was not unbounded memory growth.

Fix: refresh expiry only when an index is received for the first time. Also validate the index, total count, payload length, and constructor arguments at the reassembly entry point, preventing direct callers from bypassing the text parser's boundary checks. Valid out-of-order and duplicate fragments remain supported.

Regression coverage: a controllable clock verifies that duplicate fragments no longer extend cache lifetime. Negative or out-of-range indices, zero totals, and oversized payloads are rejected before entering the cache. Both new tests failed against the original implementation and passed after the fix.

## Validation and scope

Targeted regressions were first run against the original implementation, confirming five test failures, then verified to pass after the fixes.

- `gradlew.bat --gradle-user-home C:/Users/jinna/.gradle test build --offline` succeeded: 177 tests, with 176 passed, one skipped, and no failures or errors. The skipped storage test required symbolic-link support unavailable in the environment.
- The UTF-8 ambiguity reproduction was subsequently strengthened and encoding length-boundary tests were added. All three tests passed in a separate run of the final `PacketCodecTest`.
- `git diff --check` passed. The build emitted existing deprecated-API and JNA native-access notices.

This review did not mathematically prove the security of third-party cryptographic algorithms or test live connections between Minecraft clients and servers. Passing tests show that the covered behavior matches expectations; they do not guarantee that the project has no other vulnerabilities.

## Second review round (2026-09-12)

### 4. [P2] The receiver did not enforce session expiry and usage limits

Location: the `SESSION_MESSAGE` branch in `ChatReceiveHandler`.

The sender and session-status display used `SessionService.isExpired` to check TTL, cumulative message count, and cumulative byte count, but the receiver did not. A peer holding an old session key could therefore generate messages with fresh timestamps and valid sequence numbers that were accepted locally even though the session was otherwise considered expired. This was a failure to enforce local session policy, not an AEAD forgery without possession of the key.

Fix: perform the same session-expiry check on the receiver before decryption. Rejection does not consume replay records, advance session sequence numbers, or display the message.

Regression coverage: `expiredSessionsRejectFreshAuthenticatedMessagesWithoutAdvancingState` covers all three expiry conditions, verifies that persisted state and displayed messages remain unchanged, and uses a valid session as a successful control. Before the fix, the test reproduced display of messages from expired sessions.

### 5. [P2] Writing a new file after master-key loss generated a replacement key

Location: `SensitiveFileStore.loadMasterKey`.

Previously, the decision to generate a master key depended only on whether the current write target was already encrypted. After deleting the original master key, a new store instance writing to a new path within the account generated a replacement master key, even when other paths still contained old ciphertext. This could leave one account with files encrypted under different master keys, making it impossible to decrypt all files with a single key when restoring a backup.

Fix: when creating a master key, inspect the account directory while holding the existing interprocess lock. If encrypted files already exist, refuse generation and request restoration of the original key. The scan does not follow links and retains storage-path validation. Normal first-time initialization and concurrent creation remain supported.

Regression coverage: `missingMasterKeyCannotBeReplacedByWritingANewFile` reproduces the original behavior, verifies that failure leaves no replacement key or new file and preserves the original ciphertext, and confirms successful reads after restoring the original master key.

### 6. [P2] A failed simultaneous handshake destroyed the pending handshake prematurely

Location: `SessionHandshakeService.completeRequest`.

When handling handshakes initiated simultaneously by both peers, the original implementation removed the local pending record and destroyed its ephemeral private key before validating the peer's ephemeral public key, constructing and sending the response, and saving the session. If the peer's key was invalid or response delivery failed, no new session was established, and a valid response to the original local request could no longer be decrypted. Inputs still had to pass the existing identity and signature checks; this issue affected handshake recovery and availability.

Fix: remove the superseded pending handshake and destroy its ephemeral private key only after the response-send callback and session persistence both succeed. On failure, retain the original record and its existing expiry-cleanup behavior.

Regression coverage: `HandshakeFailureRecoveryTest` simulates an invalid ephemeral public key and a throwing send callback, then completes a valid response to the original local request and verifies that both peers obtain the same session key. Before the fix, both scenarios failed because the pending record had been lost.

All four new reproduction cases in the second round failed before the fixes. The related storage, session, and handshake tests passed afterward. These changes do not modify the network wire format.

Full second-round validation: `gradlew.bat --gradle-user-home C:/Users/jinna/.gradle test build --offline` succeeded with 182 tests: 181 passed, one skipped because Windows lacked permission to create symbolic links, and no failures or errors. `git diff --check` passed. Live client connectivity was not tested.
