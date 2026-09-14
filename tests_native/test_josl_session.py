"""Pin the JOSL session to frames the appliance's own library produced.

Every `frame` below came out of `libjsecclient.so` (arm64/x86_64 ship the same
logic) driven through its public entry points with the fixed inputs at the top,
on 2026-09-13. They are the reference, not this implementation's output: if a
change here stops reproducing them, this code is wrong and the grill would
reject it. The generator is recorded in
docs/adr/0004-local-ble-secure-session.md.
"""

import unittest

from custom_components.weber_connect.josl_session import (
    JoslSecureSession,
    JoslSecureSessionError,
    is_encrypted_type,
)

COMPANION = bytes((i * 7 + 3) & 0xFF for i in range(64))
APPLIANCE = bytes((i * 11 + 5) & 0xFF for i in range(64))
NONCE = bytes((i * 13 + 17) & 0xFF for i in range(32))

SESSION_KEY = bytes.fromhex("52bb4683202387e714bacc044bf5705f5f70f54b04ccba14e78723208346bb52")

# (message type, body, framed bytes) in the order one session emits them: the
# counter and verification code chain, so these cannot be reordered.
VECTORS = [
    (0x0C, "01010102024006", "ab01120c07004782212185a7129054"),
    (0x0C, "010101", "ab02ba0c03008221220a54"),
    (0x05, "", "ab03220500000c54"),
    (0x80, "000102030405060708090a0b0c0d0e0f", "ab0000801000000102030405060708090a0b0c0d0e0f7b54"),
    (0x8F, "0001020304", "ab00008f050000010203045554"),
    (0x90, "0001020304", "ab04bc9005002386e517bea254"),
    (0x0C, "01010202023603", "ab05500c070086e616b8ce32489954"),
]


def _session() -> JoslSecureSession:
    return JoslSecureSession(COMPANION, APPLIANCE, NONCE)


class JoslSessionTests(unittest.TestCase):
    def test_derived_key_matches_the_library(self) -> None:
        self.assertEqual(_session().key, SESSION_KEY)

    def test_key_is_palindromic(self) -> None:
        # The fold overlaps itself, so this holds for every session. It is the
        # cheapest way to catch a reimplementation that mirrors the digest.
        key = _session().key
        self.assertEqual(key, key[::-1])

    def test_wrapped_frames_match_the_library(self) -> None:
        session = _session()
        for message_type, body, expected in VECTORS:
            with self.subTest(type=message_type, length=len(body) // 2):
                self.assertEqual(
                    session.wrap(message_type, bytes.fromhex(body)).hex(),
                    expected,
                )

    def test_status_range_is_left_in_the_clear(self) -> None:
        # 0x80-0x8f is the appliance's own reporting range and must never be
        # encrypted, or a paired grill stops being readable.
        for message_type in range(0x80, 0x90):
            self.assertFalse(is_encrypted_type(message_type))
        for message_type in (0x00, 0x05, 0x0C, 0x7F, 0x90, 0xF0, 0xFF):
            self.assertTrue(is_encrypted_type(message_type))

    def test_plaintext_frames_do_not_consume_the_counter(self) -> None:
        session = _session()
        session.wrap(0x80, b"\x01\x02")
        session.wrap(0x8F, b"\x03")
        self.assertEqual(
            session.wrap(0x0C, bytes.fromhex("01010102024006")).hex(),
            VECTORS[0][2],
        )

    def test_counter_wraps_at_one_byte(self) -> None:
        session = _session()
        for _ in range(255):
            session.wrap(0x0C, b"\x01")
        self.assertEqual(session.wrap(0x0C, b"\x01")[1], 0x00)

    def test_round_trip_through_unwrap(self) -> None:
        sender = _session()
        receiver = _session()
        for index in range(8):
            body = bytes(range(index * 3))
            message_type, plain = receiver.unwrap(sender.wrap(0x0C, body))
            self.assertEqual((message_type, plain), (0x0C, body))

    def test_unwrap_passes_through_unencrypted_telemetry(self) -> None:
        session = _session()
        frame = _session().wrap(0x80, bytes(range(16)))
        self.assertEqual(session.unwrap(frame), (0x80, bytes(range(16))))

    def test_oversized_body_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            _session().wrap(0x0C, bytes(0x1000))

    def test_key_material_lengths_are_checked(self) -> None:
        with self.assertRaises(ValueError):
            JoslSecureSession(COMPANION[:63], APPLIANCE, NONCE)
        with self.assertRaises(ValueError):
            JoslSecureSession(COMPANION, APPLIANCE[:63], NONCE)
        with self.assertRaises(ValueError):
            JoslSecureSession(COMPANION, APPLIANCE, NONCE[:31])


class JoslUnwrapRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = _session()
        self.frame = bytearray(_session().wrap(0x0C, bytes.fromhex("01010102024006")))

    def _expect_rejection(self, frame: bytes) -> None:
        with self.assertRaises(JoslSecureSessionError):
            self.session.unwrap(frame)

    def test_short_frame(self) -> None:
        self._expect_rejection(b"\xab\x00\x00")

    def test_wrong_header(self) -> None:
        self.frame[0] = 0xAA
        self._expect_rejection(bytes(self.frame))

    def test_truncated_body(self) -> None:
        self._expect_rejection(bytes(self.frame[:-1]))

    def test_wrong_tail(self) -> None:
        self.frame[-1] = 0x55
        self._expect_rejection(bytes(self.frame))

    def test_bad_crc(self) -> None:
        self.frame[-2] ^= 0xFF
        self._expect_rejection(bytes(self.frame))

    def test_out_of_sequence(self) -> None:
        # Counter 2 arriving first: the appliance refuses this and so must we,
        # otherwise a replayed frame decrypts against the wrong keystream.
        sender = _session()
        sender.wrap(0x0C, b"\x01")
        self._expect_rejection(sender.wrap(0x0C, b"\x01"))

    def test_bad_verification_code(self) -> None:
        self.frame[2] ^= 0xFF
        self.frame[-2] = 0
        recomputed = bytearray(self.frame)
        from custom_components.weber_connect.saber_frames import crc8

        recomputed[-2] = crc8(bytes(recomputed[1:-2]))
        self._expect_rejection(bytes(recomputed))


if __name__ == "__main__":
    unittest.main()
