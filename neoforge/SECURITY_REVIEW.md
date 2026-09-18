# NeoForge review (2026-09-18)

Scope: NeoForge chat transport, receive handling, optional sharing, and client
lifecycle. Changes are confined to `neoforge/`; Fabric and shared sources are
unchanged. These findings do not demonstrate a break of the cryptography.

## Fixed findings

1. **Pending chat sends survived connection changes (P2).** Every message created
   a daemon thread, and each fragment looked up the current Minecraft connection.
   Disconnecting and joining a different server could send the remaining
   ciphertext and recipient metadata there. Repeated sends also created an
   unbounded number of threads, calling chat/command APIs off the client thread.
   A client-tick queue now binds work to the connection at admission, rejects
   disconnected admission, limits pending work to 2048 fragments, and sends at
   most one fragment per tick while respecting the configured delay. Logout,
   sender reconfiguration, and transport exceptions clear pending work. Queue
   admission rejects a whole message when capacity is insufficient.

2. **Cached resend bypassed the current trust policy (P2).** The resend path sent
   cached fragments without checking whether the recipient had since been
   distrusted or their imported identity removed. Both resend commands now use
   the current identity and the same trust check as an ordinary send. This does
   not re-encrypt old ciphertext for a replacement key.

3. **Invalid receive filters escaped event handling (P2, configuration-dependent).**
   `handle` extracted the fragment before entering its exception handler, and
   `shouldHide` also compiled the configured regex without protection. A malformed
   local regex therefore raised an uncaught exception when a matching fragment
   arrived. Invalid or null filters now reject the fragment without hiding the
   original chat message. This fix concerns syntax errors, not regex runtime
   complexity.

The payload callback also now ignores chat packets when initialization has not
produced a receiver, avoiding a null dereference after storage/key initialization
failure.

## Validation

- Five queue tests cover server switching, disconnect, bounded atomic admission,
  ordering, client-thread execution, pacing, cancellation, and failure recovery.
- The receive-filter regression failed with `PatternSyntaxException` when the
  original implementation was restored, and passed with the fix.
- `gradlew.bat -p neoforge test build --offline`: seven tests passed, including the
  existing Cloth Config integration metadata test.
- Resend trust enforcement and the initialization guard were checked by code
  inspection and compilation; no live Minecraft connection test was performed.

Queued sends are cancelled on settings save because that reapplies the sender.
The queue is globally paced, so concurrent messages no longer multiply the send
rate. Tests do not establish that the entire mod is free of vulnerabilities.
