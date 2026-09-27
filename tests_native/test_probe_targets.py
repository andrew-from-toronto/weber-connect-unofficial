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
    WeberShutdownButton,
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
    build_fetch_program_details_body,
    build_plan_payload_bodies,
    build_probe_target_plan,
    build_session_command_body,
    parse_program_details_payload,
    probe_target_from_program,
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
    coordinator._plan_sent = {}
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
        assert len(buttons) == 3
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


# What the grill sent back for the program HA uploaded: probe 1, plan 1, 145 F.
DETAILS_145F = (
    bytes([1, 0])
    + bytes(16)
    + bytes([1])
    + bytes.fromhex("09 5072696d6974697665 00 01 02 00000000 0080 01 74020000 03 02 00 00")
)


def test_program_details_decode_to_the_probe_target_the_app_shows() -> None:
    details = parse_program_details_payload(10, DETAILS_145F)
    assert details is not None
    assert details["session_index"] == 0
    assert details["plan_id"] == 1
    assert details["program_id_hex"] == "00" * 16
    assert details["steps"][0]["cooking_temp_dc"] is None
    assert probe_target_from_program(details, 2) == 628
    # An unknown active step falls back to the last one, as the app does.
    assert probe_target_from_program(details, 9) == 628


def test_program_details_walk_a_wide_multi_step_program() -> None:
    step_one = bytes([1, 0]) + bytes(4) + (1000).to_bytes(2, "little") + bytes([0, 2, 1])
    step_two = (
        bytes([7, 0])
        + bytes(4)
        + b"\x00\x80"
        + bytes([1])
        + (900).to_bytes(4, "little")
        + bytes([9, 2, 0])
    )
    payload = (
        bytes([1, 2])
        + bytes(range(16))
        + (5).to_bytes(4, "little")
        + bytes([1, 0x41, 0])
        + (2).to_bytes(2, "little")
        + step_one
        + step_two
        + bytes([0, 0])
    )
    details = parse_program_details_payload(11, payload)
    assert details is not None
    assert details["plan_id"] == 5
    assert [step["id"] for step in details["steps"]] == [1, 7]
    assert details["steps"][0]["cooking_temp_dc"] == 1000
    # The active step has only a probe floor, so there is no ceiling target.
    assert probe_target_from_program(details, 7) is None
    assert probe_target_from_program({"steps": []}, 1) is None


def test_program_details_before_rocket_carry_no_step_cook_mode() -> None:
    # Drop the step's cook-mode byte: requirement, then straight to prompts.
    details = parse_program_details_payload(9, DETAILS_145F[:-2] + bytes(1))
    assert details is not None
    assert probe_target_from_program(details, 2) == 628


def test_truncated_program_details_are_refused() -> None:
    assert parse_program_details_payload(10, DETAILS_145F[:-6]) is None
    assert build_fetch_program_details_body(1, 3) == bytes([1, 3])


class RecordingSession:
    def __init__(self) -> None:
        self.requests: list[tuple[int, int]] = []

    def request_program_details(self, session_type: int, session_index: int) -> None:
        self.requests.append((session_type, session_index))


def test_a_running_program_is_read_back_and_a_finished_one_clears() -> None:
    coordinator, _transport = _coordinator()
    session = RecordingSession()
    coordinator.ble_session = session
    row = {"state": "ACTIVE_FIXED", "program_id_hex": ":".join(["00"] * 16), "plan_id": 1}
    row.update(session_id=4, step_id=2)
    coordinator._probe_sessions[1] = row

    coordinator._reconcile_probe_targets({})
    coordinator._reconcile_probe_targets({})
    assert session.requests == [(1, 0)]  # asked once, not every tick

    details = parse_program_details_payload(10, DETAILS_145F)
    coordinator._reconcile_probe_targets({0: details})
    assert coordinator.probe_targets[1] == 62.8

    # A program whose details say nothing usable leaves the target alone.
    coordinator._reconcile_probe_targets({0: {**details, "steps": []}})
    assert coordinator.probe_targets[1] == 62.8

    coordinator._probe_sessions[1] = {"state": "PROBED"}
    coordinator._reconcile_probe_targets({})
    assert coordinator.probe_targets[1] is None


def test_a_target_just_sent_survives_the_appliance_catching_up() -> None:
    coordinator, _transport = _coordinator()
    coordinator.probe_targets[1] = 62.8
    coordinator._target_sent_at[1] = coordinator_module.time.monotonic()
    coordinator._probe_sessions[1] = {"state": "PROBED"}
    coordinator._reconcile_probe_targets({})
    assert coordinator.probe_targets[1] == 62.8


def test_status_keeps_only_rows_that_name_a_probe() -> None:
    coordinator, _transport = _coordinator()
    coordinator.successful_updates = 0
    coordinator._reconcile_probe_targets = MagicMock()
    coordinator.hass = MagicMock()
    coordinator.entry = SimpleNamespace(entry_id="entry", unique_id=None)
    coordinator.source = "bluetooth"
    coordinator.async_set_updated_data = MagicMock()
    with (
        patch.object(coordinator_module.ir, "async_delete_issue"),
        patch.object(coordinator_module.dr, "async_get"),
    ):
        coordinator._async_status({"probes": [{"probe_number": None}, {"probe_number": 2}]})
    assert list(coordinator._probe_sessions) == [2]


def test_the_replaced_program_is_not_read_back_over_the_new_target() -> None:
    """Measured 2026-09-27: 155 set, and the old program's 150 read back over it."""

    coordinator, _transport = _coordinator()
    coordinator.ble_session = RecordingSession()
    coordinator._probe_sessions[1] = {
        "state": "ACTIVE_FIXED",
        "program_id_hex": "",
        "plan_id": 1,
        "step_id": 2,
    }
    coordinator.probe_targets[1] = 68.3
    coordinator._plan_sent[1] = 2
    old = parse_program_details_payload(10, DETAILS_145F)  # plan 1, 145 F

    coordinator._reconcile_probe_targets({0: old})
    assert coordinator.probe_targets[1] == 68.3

    coordinator._probe_sessions[1] = {**coordinator._probe_sessions[1], "plan_id": 2}
    coordinator._reconcile_probe_targets({0: old})
    assert coordinator.probe_targets[1] == 68.3  # stale details for plan 1 do not match plan 2
    assert 1 not in coordinator._plan_sent


async def test_shutdown_sends_mode_none_with_no_target_and_only_to_a_lit_grill() -> None:
    coordinator = _entity_coordinator("bluetooth")
    coordinator.async_set_cook_mode = AsyncMock()
    button = WeberShutdownButton(coordinator, _entry())  # type: ignore[arg-type]

    coordinator.data = {"device_state": "idle"}
    with pytest.raises(HomeAssistantError, match="not lit"):
        await button.async_press()
    coordinator.async_set_cook_mode.assert_not_awaited()

    coordinator.data = {"device_state": "active"}
    await button.async_press()
    coordinator.async_set_cook_mode.assert_awaited_once_with(0)


def test_shutdown_is_the_apps_own_bytes() -> None:
    # ShutDownGrillAction: SetCookModeMessage(v10, NONE, no target) -> 00 00 80.
    from custom_components.weber_connect.saber_frames import build_set_cook_mode_body

    assert build_set_cook_mode_body(10, 0, None) == bytes([0x00, 0x00, 0x80])
