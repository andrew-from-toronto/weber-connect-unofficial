# ADR 0004: Local Bluetooth command and control

## Status

Implemented, and unverified against hardware. The session construction
(`josl_session.py`), the local transport (`ble_session.py`), the pairing storage
it needs and the coordinator wiring are all in place and covered by tests. No
part of it has yet exchanged a frame with a real appliance.

## Context

ADR 0003 routed all live telemetry through the cloud companion because "the
available protocol evidence does not establish a compatible signature, MAC, key
agreement, or verified sequence contract for subsequent status frames." That was
an accurate reading of the evidence then available. The evidence now exists, and
it changes what is possible locally.

Two separate findings drive this.

**The cloud companion socket cannot carry a command at all.** Measured against a
lit grill on 2026-09-13: `OUTGOING_SET_COOK_MODE` was sent three times over an
established, healthy socket (1 connection, 0 failures), in both the tagged
message-version-11 body and the bare version-10 body, and the appliance neither
acted on it nor answered. Not an error frame, not a rejection - silence. Every
*fetch* on the same socket is answered (`0x05`→`0x80`, `0x07`→`0x83`,
`0x0B`→`0x86`, `0x0E`→`0x88`). The one message type that writes is discarded. So
a cloud-side setpoint control is not a tuning problem; it is not available.

**The local secure session is recoverable.** The Weber Connect Android app puts
this in a native library, which is why it was previously opaque. Reversing
`libjsecclient.so` (unstripped, and its five JNI entry points name
`com.junelife.sdk.cloud.security.BleEncryptorImpl`) gives the whole construction:

* **There is no key agreement.** The app's `DefaultCipher` generates the
  "companion key pair" as two independent 64-byte `SecureRandom` blobs with no
  curve involved. The 64 bytes each side sends at pairing are shared secrets,
  learned when a person physically confirms pairing on the appliance. This is
  what ADR 0003 was looking for and did not find: the trust boundary is the
  physical pairing confirmation, not a signature.
* **The session key** is
  `SHA256(0x05 || companion_pub[64] || nonce[32] || 0x01 || appliance_pub[64])`,
  folded in place two bytes at a time. The fold overlaps itself - its second
  half reads bytes the first half already rewrote - so the result is palindromic
  (`key[i] == key[31 - i]`). Mirroring the digest instead gives a key that is
  correct for exactly half its length.
* **The verified sequence contract** ADR 0003 wanted is a per-direction one-byte
  counter plus a rolling verification code, `crc8(key[counter % 32], previous)`,
  stepping to the next key byte if that lands on zero (zero is reserved to mean
  "this frame is in the clear"). The appliance refuses a frame whose counter is
  not exactly one past the last accepted, so frames cannot be replayed or
  reordered, and a session cannot be shared between two senders.
* **The body cipher is a repeating XOR**, `body[j] ^= key[(counter + 1 + j) % 32]`.
  The library contains SHA-256 and a CRC and nothing else - no AES, no ChaCha,
  no HMAC. This is weak, and it is also the only thing the appliance accepts.
* **Status frames stay in the clear.** The encrypt/plaintext decision is a
  *signed* byte compare against `0x90`, which carves out exactly `0x80`-`0x8F` -
  every incoming status and response type. A paired appliance keeps reporting
  telemetry unencrypted even with a session established.

That last point is why the two halves of this are independent: reading needs no
session, and only the command path does.

## Decision

Take the whole appliance link local when the entry holds the material for it.

`josl_session.py` carries the session construction. Its frames were compared
byte for byte against `libjsecclient.so` over 36000 wraps spanning both body
parities, the plaintext gate, passthrough mode and counter rollover, with zero
differences; the vectors in `tests_native/test_josl_session.py` are that
library's output rather than this implementation's.

`ble_session.py` is the transport: connect, greet with `0x70` and a fresh
32-byte nonce, derive the session from the answer, then fetch and command inside
it. Reading is not a lesser capability than commanding here - the app marks the
status fetches `requiresEncryption` too - so a local link either does both or
neither.

**The transport is chosen by what the entry stores, not by an option.** The
session material only exists if the user paired after this change, and an option
offering local operation without the secrets behind it would be a setting that
silently does nothing. Re-pairing is the opt-in. The cost is real and should be
stated where a user will meet it: an appliance accepts one Bluetooth owner at a
time, so a locally-driven grill is one the phone app cannot reach.

ADR 0003's conclusion stands unchanged for telemetry frames themselves: a status
frame is still unauthenticated and still forgeable by whatever peer holds the
connection. What changed is that the *peer* can now be authenticated, because
the appliance only answers a fetch it could decrypt. The transport therefore
publishes only what arrives in reply to its own encrypted request, on a link
whose handshake succeeded. Unsolicited local telemetry is still not listened to,
and `home_assistant_only` is not reinstated.

The release validator's privacy rule is inverted rather than removed. It used to
forbid a persisted constant for this material, which was right while nothing
could use it; it now *requires* both constants to exist, and the existing rule
that diagnostics redact them is what keeps the guarantee that mattered. The
companion private key stays transient - nothing derives anything from it.

## Consequences

- **Existing installations keep using the cloud** and are unaffected. The
  appliance offers its half of the material exactly once, during pairing, so
  there is no migration: adopting local control means pairing again.
- **The config entry now holds a shared secret.** It sits beside the cloud
  password and is redacted in diagnostics by name.
- Two transports now exist behind one `_TransportSession` protocol, and
  `async_send_command` is part of that protocol rather than a cloud-only method.

**Nothing here has touched a real appliance.** Every test drives a fake GATT
client, so what is proven is that the implementation does what this document
says - not that the appliance agrees. The specific unverified claim is the one
that matters most: that a paired companion can open a session over BLE and have
a `0x0C` accepted. That is what the app does, and the identical assumption about
the cloud path turned out to be wrong. The first real test should be a setpoint
change on a lit grill with a person watching the grill, not the logs.
