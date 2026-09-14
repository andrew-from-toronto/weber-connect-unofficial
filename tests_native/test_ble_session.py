"""Local Bluetooth transport: handshake, encrypted fetch, and command writes."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.weber_connect import ble_session as transport
from custom_components.weber_connect.ble_session import (
    BleSessionKeys,
    WeberBluetoothPairingError,
    WeberBluetoothSession,
)
from custom_components.weber_connect.bluetooth import WeberBluetoothError
from custom_components.weber_connect.josl_session import JoslSecureSession
from custom_components.weber_connect.saber_frames import (
    COMMAND_UUID,
    build_appliance_payload,
    build_transport_frame,
    wrap_null_session,
)

ADDRESS = "AA:BB:CC:DD:EE:FF"
COMPANION_ID = "11" * 16
KEYS = BleSessionKeys.from_hex("33" * 64, "44" * 64)
VERSION = 10


def _reply(type_value: int, payload: bytes = b"", sequence: int = 1) -> bytes:
    """Build a frame shaped like the appliance's own plaintext reply."""

    body = build_appliance_payload(VERSION, type_value, payload)
    return build_transport_frame(sequence, wrap_null_session(body))


def _appliance_status_payload() -> bytes:
    # tag 1 = probe count, tag 2 = burner count, in the one-byte TLV the
    # appliance-status frame uses.
    return bytes([1, 1, 2, 2, 1, 1])


class FakeClient:
    """A connected GATT client that records writes and replays scripted frames."""

    def __init__(self) -> None:
        self.callbacks: dict[str, Any] = {}
        self.writes: list[bytes] = []
        self.disconnected = False
        self.is_connected = True
        self.script: list[bytes] = []

    async def start_notify(self, uuid: str, callback: Any) -> None:
        self.callbacks[uuid] = callback

    async def stop_notify(self, uuid: str) -> None:
        self.callbacks.pop(uuid, None)

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = True) -> None:
        if uuid == COMMAND_UUID:
            self.writes.append(bytes(data))
        self.flush()

    def push(self, *frames: bytes) -> None:
        self.script.extend(frames)

    def flush(self) -> None:
        callback = self.callbacks.get(transport.RESPONSE_UUID)
        if callback is None:
            return
        while self.script:
            callback(None, bytearray(self.script.pop(0)))

    async def disconnect(self) -> None:
        self.disconnected = True
        self.is_connected = False


def _session(client: FakeClient | None = None) -> WeberBluetoothSession:
    session = WeberBluetoothSession(SimpleNamespace(), ADDRESS, COMPANION_ID, KEYS, VERSION)
    if client is not None:
        session._client = client
    return session


class NotifyingClient(FakeClient):
    """Answers the handshake and then every fetch, like a healthy appliance.

    It cannot read the request type once a session exists - the body is
    encrypted by then, which is the whole point - so after the handshake it
    answers every write with the pair a fetch is waiting on. `_async_fetch`
    consumes replies until it sees a session status, so extra frames simply
    queue for the next round.
    """

    def __init__(self) -> None:
        super().__init__()
        self.handshaken = False

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = True) -> None:
        if uuid != COMMAND_UUID:
            return
        self.writes.append(bytes(data))
        if not self.handshaken:
            # Still plaintext: the appliance payload's type byte is readable at
            # transport header + envelope header + message version.
            if bytes(data)[6 + 6 + 1] == transport.OUTGOING_HANDSHAKE_GREETING:
                self.handshaken = True
                self.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
        else:
            self.push(
                _reply(transport.INCOMING_APPLIANCE_STATUS, _appliance_status_payload()),
                _reply(transport.INCOMING_STATUS, b""),
            )
        self.flush()


def test_session_keys_decode_from_hex() -> None:
    assert len(KEYS.companion_public_key) == 64
    assert len(KEYS.appliance_public_key) == 64


def test_decode_transport_rejects_short_and_mismatched_frames() -> None:
    assert transport._decode_transport(b"\x00\x01") is None
    good = _reply(transport.INCOMING_STATUS)
    assert transport._decode_transport(good) is not None
    assert transport._decode_transport(good[:-1]) is None


def test_outgoing_frames_are_plaintext_until_a_session_exists() -> None:
    session = _session()
    plain = session._frame(transport.OUTGOING_FETCH_STATUS, b"")
    # Envelope starts at byte 6; a null-session envelope has count and code zero.
    assert plain[6] == 0xAB
    assert plain[7] == 0 and plain[8] == 0
    session._session = JoslSecureSession(
        KEYS.companion_public_key, KEYS.appliance_public_key, bytes(32)
    )
    secured = session._frame(transport.OUTGOING_FETCH_STATUS, b"")
    assert secured[7] == 1 and secured[8] != 0
    forced = session._frame(transport.OUTGOING_FETCH_STATUS, b"", plaintext=True)
    assert forced[7] == 0 and forced[8] == 0


def test_sequence_wraps_at_four_bytes() -> None:
    session = _session()
    session._sequence = 0xFFFFFFFF
    assert session._next_sequence() == 0xFFFFFFFF
    assert session._next_sequence() == 0


def test_unwrap_discards_malformed_and_short_frames() -> None:
    session = _session()
    assert session._unwrap(b"\xab\x00\x00") is None
    # Structurally valid but with a body too short to hold an appliance header.
    assert session._unwrap(wrap_null_session(b"\x01")) is None
    session._session = JoslSecureSession(
        KEYS.companion_public_key, KEYS.appliance_public_key, bytes(32)
    )
    assert session._unwrap(b"\xab\x00\x00") is None


@pytest.mark.asyncio
async def test_handshake_derives_a_session_and_records_types() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    assert session.is_secure
    assert transport.INCOMING_HANDSHAKE_SUCCESS in session.received_types


@pytest.mark.asyncio
async def test_handshake_required_is_also_accepted() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_REQUIRED))
    await session._async_handshake(client)
    assert session.is_secure


@pytest.mark.asyncio
async def test_handshake_skips_unrelated_replies() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(
        _reply(transport.INCOMING_APPLIANCE_STATUS, _appliance_status_payload()),
        _reply(transport.INCOMING_HANDSHAKE_SUCCESS),
    )
    await session._async_handshake(client)
    assert session.is_secure


@pytest.mark.asyncio
async def test_pairing_required_is_fatal() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_PAIRING_REQUIRED))
    with pytest.raises(WeberBluetoothPairingError):
        await session._async_handshake(client)


@pytest.mark.asyncio
async def test_silent_appliance_fails_the_handshake() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    with patch.object(transport, "HANDSHAKE_TIMEOUT", 0.01):
        with pytest.raises(WeberBluetoothError, match="handshake"):
            await session._async_handshake(client)


@pytest.mark.asyncio
async def test_fetch_merges_appliance_status_and_capabilities() -> None:
    client = NotifyingClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    status = await session._async_fetch(client)
    assert status is not None
    assert status["kind"] == "cook_session_status"
    assert status["probe_count"] == 0


@pytest.mark.asyncio
async def test_fetch_reports_an_appliance_error_frame() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    client.push(_reply(transport.INCOMING_ERROR_MESSAGE, b"\x01\x01\x01"))
    with pytest.raises(WeberBluetoothError, match="rejected"):
        await session._async_fetch(client)


@pytest.mark.asyncio
async def test_fetch_times_out_into_none() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    with patch.object(transport, "STATUS_TIMEOUT", 0.01):
        assert await session._async_fetch(client) is None


@pytest.mark.asyncio
async def test_capabilities_are_fetched_once_and_kept() -> None:
    client = NotifyingClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    session._capabilities = {"sku": "X"}
    before = len(client.writes)
    await session._async_fetch(client)
    # Appliance status and session status only: capabilities are already held.
    assert len(client.writes) - before == 2


@pytest.mark.asyncio
async def test_command_requires_an_established_session() -> None:
    session = _session()
    with pytest.raises(WeberBluetoothError, match="not connected"):
        await session.async_send_command(0x0C, b"\x01")
    client = FakeClient()
    session._client = client
    with pytest.raises(WeberBluetoothError, match="not connected"):
        await session.async_send_command(0x0C, b"\x01")


@pytest.mark.asyncio
async def test_command_is_written_inside_the_session() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    client.writes.clear()
    await session.async_send_command(0x0C, bytes([1, 1, 1, 2, 2, 0x40, 0x06]))
    assert len(client.writes) == 1
    frame = client.writes[0]
    # Encrypted: the envelope carries a counter and a non-zero verification code.
    assert frame[7] != 0 and frame[8] != 0


@pytest.mark.asyncio
async def test_run_publishes_status_then_closes() -> None:
    client = NotifyingClient()
    session = _session()
    published: list[dict[str, Any]] = []
    errors: list[str] = []

    async def stop_after_first(status: dict[str, Any]) -> None:
        published.append(status)

    with (
        patch.object(transport, "_connect", AsyncMock(return_value=client)),
        patch.object(transport, "STATUS_INTERVAL", 0.01),
    ):
        task = asyncio.create_task(
            session.async_run(lambda status: published.append(status), errors.append)
        )
        for _ in range(200):
            await asyncio.sleep(0.01)
            if published:
                break
        await session.async_close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert published
    assert published[0]["kind"] == "cook_session_status"
    assert errors == []
    assert client.disconnected
    assert session.socket_connections == 1


@pytest.mark.asyncio
async def test_run_reports_pairing_loss_and_stops() -> None:
    client = FakeClient()
    client.push(_reply(transport.INCOMING_PAIRING_REQUIRED))
    session = _session()
    errors: list[str] = []
    with patch.object(transport, "_connect", AsyncMock(return_value=client)):
        await session.async_run(lambda _status: None, errors.append)
    assert errors and "Pair again" in errors[0]
    assert client.disconnected


@pytest.mark.asyncio
async def test_run_retries_after_a_connection_failure() -> None:
    good = NotifyingClient()
    published: list[dict[str, Any]] = []
    errors: list[str] = []
    session = _session()
    connect = AsyncMock(side_effect=[WeberBluetoothError("no adapter"), good])
    with (
        patch.object(transport, "_connect", connect),
        patch.object(transport, "RECONNECT_DELAYS", (0.01,)),
        patch.object(transport, "STATUS_INTERVAL", 0.01),
    ):
        task = asyncio.create_task(
            session.async_run(lambda status: published.append(status), errors.append)
        )
        for _ in range(200):
            await asyncio.sleep(0.01)
            if published:
                break
        await session.async_close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert errors and errors[0] == "no adapter"
    assert published


@pytest.mark.asyncio
async def test_run_survives_a_notify_subscription_refusal() -> None:
    class PickyClient(NotifyingClient):
        async def start_notify(self, uuid: str, callback: Any) -> None:
            if uuid == transport.STATUS_UUID:
                raise RuntimeError("does not notify")
            await super().start_notify(uuid, callback)

    client = PickyClient()
    session = _session()
    published: list[dict[str, Any]] = []
    with (
        patch.object(transport, "_connect", AsyncMock(return_value=client)),
        patch.object(transport, "STATUS_INTERVAL", 0.01),
    ):
        task = asyncio.create_task(session.async_run(published.append, lambda _e: None))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if published:
                break
        await session.async_close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert published


@pytest.mark.asyncio
async def test_close_retains_only_slow_changing_hub_fields() -> None:
    client = FakeClient()
    session = _session(client)
    session._appliance_status = {"software_version": "2.0", "fuel_level": "full"}
    session._frames.put_nowait(b"junk")
    await session.async_close()
    assert session._appliance_status == {"software_version": "2.0"}
    assert session._frames.empty()
    assert client.disconnected


@pytest.mark.asyncio
async def test_cancellation_releases_the_link() -> None:
    client = NotifyingClient()
    session = _session()
    with (
        patch.object(transport, "_connect", AsyncMock(return_value=client)),
        patch.object(transport, "STATUS_INTERVAL", 5),
    ):
        task = asyncio.create_task(session.async_run(lambda _s: None, lambda _e: None))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert client.disconnected


@pytest.mark.asyncio
async def test_wake_shortens_the_idle_wait() -> None:
    client = NotifyingClient()
    session = _session()
    published: list[dict[str, Any]] = []
    with (
        patch.object(transport, "_connect", AsyncMock(return_value=client)),
        patch.object(transport, "STATUS_INTERVAL", 30),
    ):
        task = asyncio.create_task(session.async_run(published.append, lambda _e: None))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if published:
                break
        session.async_wake()
        for _ in range(200):
            await asyncio.sleep(0.01)
            if len(published) > 1:
                break
        await session.async_close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(published) > 1


@pytest.mark.asyncio
async def test_undecodable_frames_are_skipped_without_ending_the_wait() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(
        b"\x00\x01",  # too short to be a transport frame
        build_transport_frame(1, b"\xab\x00\x00"),  # transport ok, envelope not
        _reply(transport.INCOMING_HANDSHAKE_SUCCESS),
    )
    await session._async_handshake(client)
    assert session.is_secure


@pytest.mark.asyncio
async def test_fetch_absorbs_a_capabilities_frame() -> None:
    client = FakeClient()
    session = _session(client)
    await client.start_notify(transport.RESPONSE_UUID, session._notify)
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    await session._async_handshake(client)
    client.push(
        _reply(transport.INCOMING_APPLIANCE_CAPABILITIES, bytes([1, 1, 2, 3, 1, 64])),
        _reply(transport.INCOMING_STATUS, b""),
    )
    status = await session._async_fetch(client)
    assert status is not None
    assert session._capabilities["probe_count"] == 2


@pytest.mark.asyncio
async def test_a_silent_appliance_mid_session_is_reported_and_retried() -> None:
    client = FakeClient()
    client.push(_reply(transport.INCOMING_HANDSHAKE_SUCCESS))
    session = _session()
    errors: list[str] = []
    with (
        patch.object(transport, "_connect", AsyncMock(return_value=client)),
        patch.object(transport, "STATUS_TIMEOUT", 0.01),
        patch.object(transport, "RECONNECT_DELAYS", (0.01,)),
    ):
        task = asyncio.create_task(session.async_run(lambda _s: None, errors.append))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if errors:
                break
        await session.async_close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert errors and "stopped answering" in errors[0]


@pytest.mark.asyncio
async def test_run_returns_immediately_once_closed() -> None:
    session = _session()
    await session.async_close()
    connect = AsyncMock()
    with patch.object(transport, "_connect", connect):
        await session.async_run(lambda _s: None, lambda _e: None)
    connect.assert_not_called()


@pytest.mark.asyncio
async def test_idle_tick_polls_again_and_closing_ends_the_loop() -> None:
    # No explicit wake: the loop must come back on its own interval, and then
    # notice that the session was closed rather than fetching once more.
    client = NotifyingClient()
    session = _session()
    published: list[dict[str, Any]] = []
    with (
        patch.object(transport, "_connect", AsyncMock(return_value=client)),
        patch.object(transport, "STATUS_INTERVAL", 0.01),
    ):
        task = asyncio.create_task(session.async_run(published.append, lambda _e: None))
        for _ in range(300):
            await asyncio.sleep(0.01)
            if len(published) >= 3:
                break
        await session.async_close()
        # Closing ends the loop on its own; nothing has to cancel the task.
        await asyncio.wait_for(task, timeout=2)
    assert len(published) >= 3
    assert task.exception() is None


def test_coordinator_selects_bluetooth_only_with_stored_session_material() -> None:
    """The entry's own secrets decide the transport, not an option."""

    from unittest.mock import MagicMock

    from custom_components.weber_connect import coordinator as coordinator_module
    from custom_components.weber_connect.const import (
        CONF_APPLIANCE_ID,
        CONF_APPLIANCE_PUBLIC_KEY,
        CONF_CLOUD_PASSWORD,
        CONF_COMPANION_ID,
        CONF_COMPANION_PUBLIC_KEY,
    )

    def _entry(**extra: str) -> SimpleNamespace:
        return SimpleNamespace(
            data={
                "address": ADDRESS,
                CONF_COMPANION_ID: COMPANION_ID,
                CONF_CLOUD_PASSWORD: "cloud-password",
                CONF_APPLIANCE_ID: "22" * 16,
                **extra,
            },
            options={},
            entry_id="test-entry",
            unique_id=ADDRESS,
            title="Test Weber Hub",
            pref_disable_polling=False,
            async_create_background_task=MagicMock(),
            async_on_unload=MagicMock(),
        )

    hass = MagicMock()
    with patch.object(coordinator_module, "WeberCloudClient", MagicMock()):
        cloud_only = coordinator_module.WeberCoordinator(hass, _entry())  # type: ignore[arg-type]
        assert cloud_only.source == "cloud"
        assert cloud_only.ble_session is None

        local = coordinator_module.WeberCoordinator(  # type: ignore[arg-type]
            hass,
            _entry(
                **{
                    CONF_COMPANION_PUBLIC_KEY: "33" * 64,
                    CONF_APPLIANCE_PUBLIC_KEY: "44" * 64,
                }
            ),
        )
        assert local.source == "bluetooth"
        assert local.ble_session is not None
        assert local.ble_session.address == ADDRESS
