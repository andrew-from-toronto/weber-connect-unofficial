# ADR 0004: Local Bluetooth command and control

## Status

Proposed. The session construction is implemented and verified
(`custom_components/weber_connect/josl_session.py`); the transport that would
use it is not written.

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

Treat the local Bluetooth path as the route for command and control, and keep
the session implementation separate from the transport that will use it.

`josl_session.py` is committed on its own because it is verifiable without an
appliance and the transport is not. Its frames were compared byte for byte
against `libjsecclient.so` over 36000 wraps spanning both body parities, the
plaintext gate, passthrough mode and counter rollover, with zero differences;
the vectors in `tests_native/test_josl_session.py` are that library's output.

ADR 0003's conclusion stands unchanged for *telemetry*: a local status frame is
still unauthenticated, still forgeable by a nearby peer, and is not a basis for
publishing temperatures. Nothing here argues for reinstating `home_assistant_only`
reading. A command we *send* is a different question - it is authenticated by the
session, and its counter makes it unreplayable.

## Consequences

Not yet done, in dependency order:

1. **Pairing must keep both public keys.** `async_pair` currently parses the
   appliance's 64-byte public key out of the pairing response and discards it,
   and the companion public key it generated is not stored either. Both are
   required to derive a session key, so this is the blocking change - and it
   means **an existing installation has to re-pair**, because the material was
   never written down. Storing them makes the config entry hold a shared secret;
   it belongs with the cloud password, not in diagnostics.
2. **A Bluetooth transport.** `WeberCoordinator` already owns exactly one
   `_TransportSession`, so the shape exists. The connection must send the `0x70`
   handshake greeting with a fresh 32-byte nonce, derive the session from the
   response, and wrap outgoing commands. The appliance accepts one BLE owner at
   a time, so this competes with the phone app.
3. **A decision about which transport reads.** Local commands plus cloud
   telemetry is coherent (and keeps ADR 0003 intact) but holds two connections.

Untested against hardware, and worth saying explicitly: the appliance's
acceptance of a companion-originated `0x0C` over BLE has not been observed. It
is what the app does, but the same assumption about the cloud path proved wrong.
The first real test should be a setpoint change on a lit grill with a person
watching it.
