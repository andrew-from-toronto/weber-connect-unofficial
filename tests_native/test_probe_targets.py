"""Probe target programs: the app's one-step primitive, uploaded over Bluetooth."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.exceptions import HomeAssistantError

from custom_components.weber_connect import coordinator as coordinator_module
from custom_components.weber_connect.button import (
    WeberClearProbeTargetButton,
)
from custom_components.weber_connect.button import (
    async_setup_entry as async_setup_button,
)
from custom_components.weber_connect.number import (
    WeberProbeTargetNumber,
)
from custom_components.weber_connect.number import (
    async_setup_entry as async_setup_number,
)
from custom_components.weber_connect.saber_frames import (
    OUTGOING_PLAN_PAYLOAD,
    OUTGOING_SESSION_COMMAND,
    PRIMITIVE_PROGRAM_ID,
    SESSION_COMMAND_REMOVE,
    SESSION_COMMAND_START,
    build_plan_payload_bodies,
    build_probe_target_plan,
    build_session_command_body,
)

# 203 F = 95.0 C, traced by hand from CookProgramPayloadKt for message version 10.
WORKED_PLAN = bytes.fromhex("09 5072696d6974697665 00 01 02 00000000 0080 01 b6030000 03 02 00 00")


def test_primitive_plan_matches_the_apps_own_encoding() -> None:
    assert build_probe_target_plan(10, 950) == WORKED_PLAN


def test_primitive_plan_widens_ids_and_counts_from_version_11() -> None:
    plan = build_probe_target_plan(11, 950)
    # Step count, step id and prompt count each grow to u16.
    assert plan[11:13] == b"\x01\x00"
    assert plan[13:15] == b"\x02\x00"
    assert plan[-2:] == b"\x00\x00"
    assert len(plan) == len(WORKED_PLAN) + 3


def test_primitive_plan_rejects_an_unencodable_target() -> None:
    with pytest.raises(ValueError, match="signed 16-bit"):
        build_probe_target_plan(10, 40000)


def test_plan_payload_prefixes_program_plan_chunk_and_slot() -> None:
    (body,) = build_plan_payload_bodies(10, PRIMITIVE_PROGRAM_ID, 3, 1, 0, WORKED_PLAN)
    assert body == bytes(16) + bytes([3, 0, 1, 0]) + WORKED_PLAN
    (wide,) = build_plan_payload_bodies(11, PRIMITIVE_PROGRAM_ID, 3, 1, 0, WORKED_PLAN)
    assert wide[16:20] == b"\x03\x00\x00\x00"


def test_plan_payload_refuses_what_the_app_would_never_build() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        build_plan_payload_bodies(10, b"\x00", 0, 1, 0, WORKED_PLAN)
    with pytest.raises(ValueError, match="one chunk"):
        build_plan_payload_bodies(10, PRIMITIVE_PROGRAM_ID, 0, 1, 0, bytes(256))


def test_session_command_layouts() -> None:
    assert build_session_command_body(10, PRIMITIVE_PROGRAM_ID, 0, 2, 1, 0) == (
        bytes(16) + bytes([0, 2, 1, 0])
    )
    assert build_session_command_body(11, PRIMITIVE_PROGRAM_ID, 5, 4, 1, 2) == (
        bytes([1, 1, 4, 2, 1, 1, 3, 1, 2, 4, 16]) + bytes(16) + bytes([5, 4, 5, 0, 0, 0])
    )
    with pytest.raises(ValueError, match="16 bytes"):
        build_session_command_body(10, b"", 0, 2, 1, 0)


class RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[int, bytes]] = []

    async def async_send_command(self, type_value: int, payload: bytes = b"") -> None:
        self.sent.append((type_value, payload))


def _coordinator() -> tuple[Any, RecordingTransport]:
    coordinator = coordinator_module.WeberCoordinator.__new__(coordinator_module.WeberCoordinator)
    transport = RecordingTransport()
    coordinator._transport = transport
    coordinator.message_version = 10
    coordinator.probe_targets = {}
    coordinator._probe_sessions = {}
    coordinator._next_plan_id = 1
    coordinator._program_asked = {}
    coordinator._target_sent_at = {}
    coordinator.ble_session = None
    coordinator.async_update_listeners = MagicMock()
    return coordinator, transport


async def test_a_plugged_in_probe_gets_the_plan_then_start() -> None:
    coordinator, transport = _coordinator()
    coordinator._probe_sessions[1] = {"state": "PROBED", "plan_id": None}
    await coordinator.async_set_probe_target(1, 628)
    assert [type_value for type_value, _ in transport.sent] == [
        OUTGOING_PLAN_PAYLOAD,
        OUTGOING_SESSION_COMMAND,
    ]
    assert transport.sent[0][1][16:20] == bytes([1, 0, 1, 0])
    assert transport.sent[1][1][17] == SESSION_COMMAND_START
    assert coordinator.probe_targets[1] == 62.8
    coordinator.async_update_listeners.assert_called()


async def test_a_running_program_is_removed_first_and_its_plan_id_not_reused() -> None:
    coordinator, transport = _coordinator()
    coordinator._probe_sessions[2] = {
        "state": "ACTIVE_FIXED",
        "program_id_hex": "ab" * 16,
        "plan_id": 1,
    }
    with patch.object(coordinator_module.asyncio, "sleep", new=AsyncMock()) as settle:
        await coordinator.async_set_probe_target(2, 700)
    settle.assert_awaited_once()
    remove, plan, start = transport.sent
    assert remove[0] == OUTGOING_SESSION_COMMAND
    assert remove[1] == bytes.fromhex("ab" * 16) + bytes([1, SESSION_COMMAND_REMOVE, 1, 1])
    assert plan[0] == OUTGOING_PLAN_PAYLOAD
    assert plan[1][16] == 2  # plan id 1 is the running one, so it is skipped
    assert start[1][16:] == bytes([2, SESSION_COMMAND_START, 1, 1])


async def test_clear_removes_only_a_running_program() -> None:
    coordinator, transport = _coordinator()
    coordinator.probe_targets[1] = 62.8
    await coordinator.async_clear_probe_target(1)
    assert transport.sent == []
    assert coordinator.probe_targets[1] is None

    coordinator._probe_sessions[1] = {"state": "ACTIVE", "program_id_hex": None, "plan_id": 4}
    await coordinator.async_clear_probe_target(1)
    ((type_value, body),) = transport.sent
    assert type_value == OUTGOING_SESSION_COMMAND
    assert body == PRIMITIVE_PROGRAM_ID + bytes([4, SESSION_COMMAND_REMOVE, 1, 0])


def _entry() -> SimpleNamespace:
    return SimpleNamespace(
        data={"address": "AA:BB:CC:DD:EE:FF"},
        unique_id="AA:BB:CC:DD:EE:FF",
        entry_id="entry",
        title="SmokeFire",
    )


def _entity_coordinator(source: str) -> Any:
    coordinator = MagicMock()
    coordinator.source = source
    coordinator.data = {}
    coordinator.probe_targets = {1: 62.8}
    coordinator.async_set_probe_target = AsyncMock()
    coordinator.async_clear_probe_target = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    return coordinator


@pytest.mark.parametrize("source", ["bluetooth", "cloud"])
async def test_probe_target_controls_exist_only_on_a_bluetooth_entry(source: str) -> None:
    coordinator = _entity_coordinator(source)
    entry = _entry()
    entry.runtime_data = SimpleNamespace(coordinator=coordinator)
    entry.async_on_unload = MagicMock()
    numbers: list[Any] = []
    buttons: list[Any] = []
    with (
        patch("custom_components.weber_connect.number.known_probe_numbers", return_value={1, 2}),
        patch("custom_components.weber_connect.button.known_probe_numbers", return_value={1, 2}),
    ):
        await async_setup_number(MagicMock(), entry, numbers.extend)  # type: ignore[arg-type]
        await async_setup_button(MagicMock(), entry, buttons.extend)  # type: ignore[arg-type]
    probe_numbers = [entity for entity in numbers if isinstance(entity, WeberProbeTargetNumber)]
    if source == "bluetooth":
        assert len(probe_numbers) == 2
        assert len(buttons) == 2
    else:
        assert probe_numbers == []
        assert buttons == []


async def test_probe_target_number_and_clear_button_drive_the_coordinator() -> None:
    coordinator = _entity_coordinator("bluetooth")
    number = WeberProbeTargetNumber(coordinator, _entry(), 1)  # type: ignore[arg-type]
    assert number.native_value == 62.8
    await number.async_set_native_value(62.8)
    coordinator.async_set_probe_target.assert_awaited_once_with(1, 628)
    with pytest.raises(HomeAssistantError, match="probe target range"):
        await number.async_set_native_value(200.0)

    button = WeberClearProbeTargetButton(coordinator, _entry(), 1)  # type: ignore[arg-type]
    await button.async_press()
    coordinator.async_clear_probe_target.assert_awaited_once_with(1)
