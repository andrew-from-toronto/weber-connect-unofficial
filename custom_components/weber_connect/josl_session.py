"""The JOSL secure session an appliance requires before it will accept a command.

Recovered from the Weber Connect Android app 2026-09-13. The app does this in a
native library (`libjsecclient.so`, `com.junelife.sdk.cloud.security.BleEncryptorImpl`),
so none of it is visible from Java; the constants and the two folds below come
from disassembling `jsec_session_start` and `josl_secure_msg_wrap`. Every frame
this module produces has been compared byte for byte against that library across
36000 wraps spanning both body parities, the plaintext gate and counter
rollover, so the vectors in the tests are the appliance's own behaviour rather
than a reading of it.

Three things about this construction are worth stating plainly, because each one
looks like a bug until you check it against the library:

* There is no key agreement. The "public keys" exchanged at pairing are two
  independent 64-byte random blobs (the app's `DefaultCipher` generates them
  from `SecureRandom` with no curve involved), so they are shared secrets that
  the appliance learns when a person physically confirms pairing. Nothing here
  needs elliptic curve code.
* The whole session is SHA-256 and a CRC. The library contains no AES, ChaCha
  or HMAC - only the SHA-256 constants - and the body cipher is a repeating XOR
  against a 32-byte key. It is weak, but reimplementing it is the only way to
  talk to the appliance.
* The key ends up palindromic. The fold is done in place, two bytes at a time,
  and its second half reads bytes the first half has already rewritten, so the
  top 16 bytes survive unchanged and `key[i] == key[31 - i]`. Mirroring the
  digest instead produces a key that matches for exactly half its length, which
  is the kind of thing that works in a unit test and fails on the grill.
"""

from __future__ import annotations

import hashlib

from .saber_frames import crc8

# Identifiers the appliance expects for each end of the session. The app passes
# these to josl_secure_session_local/remote; they are not free choices.
COMPANION_ROLE = 5
APPLIANCE_ROLE = 1

KEY_LENGTH = 32
NONCE_LENGTH = 32
PUBLIC_KEY_LENGTH = 64

FRAME_HEADER = 0xAB
FRAME_TAIL = 0x54
MAX_BODY = 0xFFF


def is_encrypted_type(message_type: int) -> bool:
    """Return whether a message of this type travels encrypted.

    The library decides with a *signed* byte compare against 0x90, which carves
    out exactly 0x80-0x8F. That range is every incoming status and response
    frame, so an appliance keeps reporting telemetry in the clear even after a
    session is established - which is why read-only integrations work without
    implementing any of this, and why only the command path needs it.
    """

    return not 0x80 <= message_type <= 0x8F


def _derive_key(companion_public_key: bytes, appliance_public_key: bytes, nonce: bytes) -> bytes:
    digest = bytearray(
        hashlib.sha256(
            bytes([COMPANION_ROLE])
            + companion_public_key
            + nonce
            + bytes([APPLIANCE_ROLE])
            + appliance_public_key
        ).digest()
    )
    # In place and overlapping, exactly as the library does it. The shared-key
    # input the library XORs in here is all zeros for a BLE session (the JNI
    # entry point passes NULL), so it is omitted rather than carried as a
    # parameter nothing can set.
    for index in range(KEY_LENGTH // 2):
        digest[2 * index] = digest[KEY_LENGTH - 1 - 2 * index]
        digest[2 * index + 1] = digest[KEY_LENGTH - 2 - 2 * index]
    return bytes(digest)


class JoslSecureSessionError(RuntimeError):
    """A frame did not survive validation against the session."""


class JoslSecureSession:
    """One established session with a paired appliance.

    Created after the appliance answers the 0x70 handshake greeting. Both
    directions carry their own message counter and rolling verification code,
    and the appliance rejects a frame whose counter is not exactly one past the
    last one it accepted - so a session cannot be shared between two senders,
    and a dropped frame ends it.
    """

    def __init__(
        self,
        companion_public_key: bytes,
        appliance_public_key: bytes,
        nonce: bytes,
    ) -> None:
        if len(companion_public_key) != PUBLIC_KEY_LENGTH:
            raise ValueError("companion public key must be 64 bytes")
        if len(appliance_public_key) != PUBLIC_KEY_LENGTH:
            raise ValueError("appliance public key must be 64 bytes")
        if len(nonce) != NONCE_LENGTH:
            raise ValueError("nonce must be 32 bytes")
        self._key = _derive_key(companion_public_key, appliance_public_key, nonce)
        self._outgoing_counter = 0
        self._outgoing_code = 0
        self._incoming_counter = 0
        self._incoming_code = 0

    @property
    def key(self) -> bytes:
        """Expose the derived key so a test can pin it. Never send it."""

        return self._key

    def _next_code(self, counter: int, previous: int) -> int:
        code = crc8(bytes([self._key[counter % KEY_LENGTH]]), previous)
        if code == 0:
            # Zero is how an unencrypted frame announces itself, so the library
            # steps to the next key byte rather than emit a code that would read
            # as "this frame is in the clear".
            code = crc8(bytes([self._key[(counter + 1) % KEY_LENGTH]]))
        return code

    def _apply_keystream(self, counter: int, body: bytes) -> bytes:
        out = bytearray(body)
        for index in range(len(out)):
            out[index] ^= self._key[(counter + 1 + index) % KEY_LENGTH]
        return bytes(out)

    def wrap(self, message_type: int, body: bytes = b"") -> bytes:
        """Frame one message, encrypting it when its type calls for that."""

        if len(body) > MAX_BODY:
            raise ValueError("body exceeds the 0xfff the appliance accepts")
        if not is_encrypted_type(message_type):
            return _frame(0, 0, message_type, body)
        self._outgoing_counter = (self._outgoing_counter + 1) & 0xFF
        counter = self._outgoing_counter
        self._outgoing_code = self._next_code(counter, self._outgoing_code)
        return _frame(
            counter,
            self._outgoing_code,
            message_type,
            self._apply_keystream(counter, body),
        )

    def unwrap(self, frame: bytes) -> tuple[int, bytes]:
        """Validate one received frame and return its type and plaintext body.

        A frame carrying verification code zero is plaintext and is returned as
        it stands: that is the normal path for appliance telemetry, which is
        never encrypted, and it is how a frame that predates the session still
        parses.
        """

        if len(frame) < 8:
            raise JoslSecureSessionError("frame is too short to contain an envelope")
        body_length = int.from_bytes(frame[4:6], "little")
        if frame[0] != FRAME_HEADER or len(frame) != body_length + 8:
            raise JoslSecureSessionError("frame is not a complete JOSL envelope")
        if frame[body_length + 7] != FRAME_TAIL:
            raise JoslSecureSessionError("frame does not end with the expected tail byte")
        if crc8(frame[1 : body_length + 7]) != 0:
            raise JoslSecureSessionError("frame failed its CRC")
        message_type = frame[3]
        body = frame[6 : 6 + body_length]
        if frame[2] == 0:
            return message_type, body
        counter = (self._incoming_counter + 1) & 0xFF
        if frame[1] != counter:
            raise JoslSecureSessionError("frame arrived out of sequence")
        expected = self._next_code(counter, self._incoming_code)
        if frame[2] != expected:
            raise JoslSecureSessionError("frame failed its verification code")
        self._incoming_counter = counter
        self._incoming_code = expected
        return message_type, self._apply_keystream(counter, body)


def _frame(counter: int, code: int, message_type: int, body: bytes) -> bytes:
    header = bytes([counter, code, message_type]) + len(body).to_bytes(2, "little")
    return bytes([FRAME_HEADER]) + header + body + bytes([crc8(header + body), FRAME_TAIL])
