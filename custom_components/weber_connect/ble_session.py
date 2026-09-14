"""A local Bluetooth transport that can both read an appliance and drive it.

This is the half of ADR 0004 that talks to the hardware. The session crypto it
depends on lives in `josl_session.py` and is verified against Weber's own
library; everything here is the framing and connection handling around it.

What the appliance requires, taken from the app's own message definitions
(`OutgoingApplianceMessage.requiresEncryption` defaults to true):

* The handshake greeting and the pairing request go in the clear. They are what
  establishes the session, so they cannot be inside it.
* **Everything else is encrypted, including the status fetches.** Reading an
  appliance locally is therefore not a lesser capability than commanding it -
  both need the pairing secrets, and neither works without a session.
* Replies come back in the clear regardless (the appliance's own 0x80-0x8F
  range bypasses encryption), which is why the existing plaintext decoders are
  reused unchanged.

The trust boundary that follows is narrower than it looks, and is stated here so
it is not mistaken for more. An incoming status frame is *not* authenticated -
it carries verification code zero and any peer that won the connection could
produce one. What is authenticated is the peer: the appliance only answers a
fetch it could decrypt, so a reply to our own encrypted request proves the other
end holds the pairing secret. This session therefore only publishes status that
arrives in response to a fetch it sent, on a connection whose handshake
succeeded. ADR 0003's objection to listening to unsolicited local telemetry
stands and is deliberately not reopened.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from bleak import BleakClient
from homeassistant.core import HomeAssistant

from .bluetooth import WeberBluetoothError, _connect, _safe_disconnect
from .josl_session import JoslSecureSession, JoslSecureSessionError
from .saber_frames import (
    COMMAND_UUID,
    NOTIFICATION_UUID,
    RESPONSE_UUID,
    SESSION_UUID,
    STATUS_UUID,
    build_appliance_payload,
    build_handshake_body,
    build_transport_frame,
    parse_appliance_capabilities_payload,
    parse_appliance_status_payload,
    parse_cook_session_status_payload,
    wrap_null_session,
)

_LOGGER = logging.getLogger(__name__)

OUTGOING_HANDSHAKE_GREETING = 0x70
OUTGOING_FETCH_STATUS = 0x05
OUTGOING_FETCH_APPLIANCE_STATUS = 0x07
OUTGOING_FETCH_APPLIANCE_CAPABILITIES = 0x0E

INCOMING_STATUS = 0x80
INCOMING_APPLIANCE_STATUS = 0x83
INCOMING_ERROR_MESSAGE = 0x87
INCOMING_APPLIANCE_CAPABILITIES = 0x88
INCOMING_HANDSHAKE_REQUIRED = 0xF0
INCOMING_PAIRING_REQUIRED = 0xF1
INCOMING_HANDSHAKE_SUCCESS = 0xF2

NONCE_LENGTH = 32
HANDSHAKE_TIMEOUT = 10.0
STATUS_TIMEOUT = 12.0
STATUS_INTERVAL = 10.0
RECONNECT_DELAYS = (1.0, 2.0, 5.0, 10.0, 30.0)

# Retained across a dropped link so a reconnect is not reported as an appliance
# that has forgotten its slow-changing hub fields. Mirrors the cloud session.
_RETAINED_KEYS = frozenset(
    {"software_version", "hardware_version", "wifi_connection_status", "cloud_connection_status"}
)


class WeberBluetoothPairingError(WeberBluetoothError):
    """The appliance no longer recognises this companion's pairing."""


@dataclass(frozen=True, slots=True)
class BleSessionKeys:
    """The two 64-byte blobs exchanged when a person confirmed pairing.

    Both are secrets. They are not a key pair and nothing about them is public
    except the name the protocol gives them.
    """

    companion_public_key: bytes
    appliance_public_key: bytes

    @classmethod
    def from_hex(cls, companion: str, appliance: str) -> BleSessionKeys:
        return cls(bytes.fromhex(companion), bytes.fromhex(appliance))


def _decode_transport(data: bytes) -> bytes | None:
    """Return the envelope inside one transport frame, or None if malformed."""

    if len(data) < 6:
        return None
    length = int.from_bytes(data[4:6], "little")
    envelope = data[6:]
    if len(envelope) != length:
        return None
    return envelope


class WeberBluetoothSession:
    """One local Bluetooth link to a paired appliance."""

    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        companion_id: str,
        keys: BleSessionKeys,
        message_version: int,
    ) -> None:
        self.hass = hass
        self.address = address
        self.companion_id = companion_id
        self.keys = keys
        self.message_version = message_version
        self.socket_connections = 0
        self.received_types: list[int] = []
        self._client: BleakClient | None = None
        self._session: JoslSecureSession | None = None
        self._sequence = 1
        self._frames: asyncio.Queue[bytes] = asyncio.Queue()
        self._wake = asyncio.Event()
        self._appliance_status: dict[str, Any] = {}
        self._capabilities: dict[str, Any] = {}
        self._closing = False

    @property
    def is_secure(self) -> bool:
        """Whether a handshake has completed on the current link."""

        return self._session is not None

    def async_wake(self) -> None:
        """Ask the status loop to fetch now instead of waiting for its tick."""

        self._wake.set()

    def _next_sequence(self) -> int:
        sequence = self._sequence
        self._sequence = (self._sequence + 1) & 0xFFFFFFFF
        return sequence

    def _frame(self, type_value: int, payload: bytes, *, plaintext: bool = False) -> bytes:
        appliance_payload = build_appliance_payload(self.message_version, type_value, payload)
        if plaintext or self._session is None:
            envelope = wrap_null_session(appliance_payload)
        else:
            # The envelope's own type byte is zero for everything the companion
            # sends, which is inside the range the appliance expects encrypted.
            envelope = self._session.wrap(0, appliance_payload)
        return build_transport_frame(self._next_sequence(), envelope)

    async def _async_write(
        self,
        client: BleakClient,
        type_value: int,
        payload: bytes = b"",
        *,
        plaintext: bool = False,
    ) -> None:
        await client.write_gatt_char(
            COMMAND_UUID,
            self._frame(type_value, payload, plaintext=plaintext),
            response=True,
        )

    def _notify(self, _sender: Any, data: bytearray) -> None:
        self._frames.put_nowait(bytes(data))

    async def _async_next_payload(self, timeout: float) -> tuple[int, bytes] | None:
        """Wait for one decodable appliance payload, or None on timeout."""

        try:
            async with asyncio.timeout(timeout):
                while True:
                    raw = await self._frames.get()
                    envelope = _decode_transport(raw)
                    if envelope is None:
                        continue
                    decoded = self._unwrap(envelope)
                    if decoded is not None:
                        return decoded
        except TimeoutError:
            return None

    def _unwrap(self, envelope: bytes) -> tuple[int, bytes] | None:
        session = self._session
        if session is not None:
            try:
                _envelope_type, body = session.unwrap(envelope)
            except JoslSecureSessionError:
                _LOGGER.debug("Discarded an undecodable Weber frame", exc_info=True)
                return None
        else:
            # Before a session exists only the handshake replies are expected,
            # and those are plaintext. Validate the framing the same way.
            try:
                _envelope_type, body = _PLAINTEXT.unwrap(envelope)
            except JoslSecureSessionError:
                _LOGGER.debug("Discarded a malformed Weber frame", exc_info=True)
                return None
        if len(body) < 2:
            return None
        type_value = body[1]
        self.received_types = [*self.received_types[-19:], type_value]
        return type_value, body[2:]

    async def _async_handshake(self, client: BleakClient) -> None:
        """Greet the appliance and derive the session from its answer."""

        self._session = None
        nonce = secrets.token_bytes(NONCE_LENGTH)
        await self._async_write(
            client,
            OUTGOING_HANDSHAKE_GREETING,
            build_handshake_body(self.companion_id, nonce),
            plaintext=True,
        )
        while True:
            answer = await self._async_next_payload(HANDSHAKE_TIMEOUT)
            if answer is None:
                raise WeberBluetoothError(
                    "The appliance did not answer the handshake. It may be asleep or "
                    "connected to the Weber app."
                )
            type_value, _payload = answer
            if type_value == INCOMING_PAIRING_REQUIRED:
                raise WeberBluetoothPairingError(
                    "The appliance no longer recognises this companion. Pair again."
                )
            if type_value in (INCOMING_HANDSHAKE_SUCCESS, INCOMING_HANDSHAKE_REQUIRED):
                break
        self._session = JoslSecureSession(
            self.keys.companion_public_key,
            self.keys.appliance_public_key,
            nonce,
        )

    async def async_send_command(self, type_value: int, payload: bytes = b"") -> None:
        """Send one appliance command inside the established session."""

        client = self._client
        if client is None or self._session is None:
            raise WeberBluetoothError(
                "Home Assistant is not connected to the appliance over Bluetooth. "
                "Wait for the next update and try again."
            )
        await self._async_write(client, type_value, payload)
        self.async_wake()

    async def _async_fetch(self, client: BleakClient) -> dict[str, Any] | None:
        """Ask for one status and assemble it from the replies."""

        await self._async_write(client, OUTGOING_FETCH_APPLIANCE_STATUS)
        if not self._capabilities:
            await self._async_write(client, OUTGOING_FETCH_APPLIANCE_CAPABILITIES)
        await self._async_write(client, OUTGOING_FETCH_STATUS)
        while True:
            answer = await self._async_next_payload(STATUS_TIMEOUT)
            if answer is None:
                return None
            type_value, payload = answer
            if type_value == INCOMING_ERROR_MESSAGE:
                raise WeberBluetoothError("The appliance rejected a Bluetooth request.")
            if type_value == INCOMING_APPLIANCE_STATUS:
                # Partial frames arrive between full ones; merging only reported
                # values keeps one of them from blanking every hub field.
                self._appliance_status.update(
                    {
                        key: value
                        for key, value in parse_appliance_status_payload(payload).items()
                        if key not in {"kind", "unparsed_tail_hex"} and value is not None
                    }
                )
                continue
            if type_value == INCOMING_APPLIANCE_CAPABILITIES:
                self._capabilities = {
                    key: value
                    for key, value in parse_appliance_capabilities_payload(payload).items()
                    if key != "kind"
                }
                continue
            if type_value == INCOMING_STATUS:
                cook = parse_cook_session_status_payload(payload)
                return {
                    **cook,
                    **{k: v for k, v in self._appliance_status.items() if k != "kind"},
                    **self._capabilities,
                }

    async def _async_connect(self) -> BleakClient:
        client = await _connect(self.hass, self.address, max_attempts=1)
        self.socket_connections += 1
        for uuid in (RESPONSE_UUID, STATUS_UUID, NOTIFICATION_UUID):
            try:
                await client.start_notify(uuid, self._notify)
            except Exception:
                _LOGGER.debug("Appliance characteristic %s does not notify", uuid, exc_info=True)
        await client.write_gatt_char(SESSION_UUID, b"\x01", response=True)
        return client

    async def _async_drop(self) -> None:
        client, self._client = self._client, None
        self._session = None
        self._appliance_status = {
            key: value for key, value in self._appliance_status.items() if key in _RETAINED_KEYS
        }
        while not self._frames.empty():  # pragma: no branch
            self._frames.get_nowait()
        if client is not None:
            await _safe_disconnect(client)

    async def async_run(
        self,
        status_callback: Callable[[dict[str, Any]], None],
        error_callback: Callable[[str], None],
    ) -> None:
        """Hold the link open and publish status at the live cadence."""

        failures = 0
        while not self._closing:
            try:
                client = await self._async_connect()
                self._client = client
                await self._async_handshake(client)
                failures = 0
                while not self._closing:
                    status = await self._async_fetch(client)
                    if status is None:
                        raise WeberBluetoothError("The appliance stopped answering.")
                    status_callback(status)
                    self._wake.clear()
                    try:
                        async with asyncio.timeout(STATUS_INTERVAL):
                            await self._wake.wait()
                    except TimeoutError:
                        pass
            except WeberBluetoothPairingError as err:
                error_callback(str(err))
                await self._async_drop()
                return
            except asyncio.CancelledError:
                await self._async_drop()
                raise
            except Exception as err:  # one link; never let it die on a fault
                error_callback(str(err) or type(err).__name__)
                await self._async_drop()
                delay = RECONNECT_DELAYS[min(failures, len(RECONNECT_DELAYS) - 1)]
                failures += 1
                await asyncio.sleep(delay)

    async def async_close(self) -> None:
        """Release the link and forget the session."""

        self._closing = True
        self.async_wake()
        await self._async_drop()


# Only ever used to validate framing on replies that arrive before a session
# exists. Its key is irrelevant: a handshake reply carries verification code
# zero, so unwrap returns it without touching the keystream.
_PLAINTEXT = JoslSecureSession(bytes(64), bytes(64), bytes(32))
