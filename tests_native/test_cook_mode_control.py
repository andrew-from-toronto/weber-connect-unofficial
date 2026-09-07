"""Cook mode and target temperature command contracts."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.exceptions import HomeAssistantError

from custom_components.weber_connect import coordinator as coordinator_module
from custom_components.weber_connect import weber_cloud_socket as socket
from custom_components.weber_connect.const import (
    CONF_APPLIANCE_ID,
    CONF_CLOUD_PASSWORD,
    CONF_COMPANION_ID,
    CONF_MESSAGE_VERSION,
)
from custom_components.weber_connect.coordinator import WeberCoordinator
from custom_components.weber_connect.number import (
    WeberTargetTemperatureNumber,
)
from custom_components.weber_connect.number import (
    async_setup_entry as async_setup_number,
)
from custom_components.weber_connect.saber_frames import (
    COOK_MODE_VALUES,
    COOK_MODES,
    build_set_cook_mode_body,
)
from custom_components.weber_connect.select import (
    COOK_MODE_OPTIONS,
    WeberCookModeSelect,
)
from custom_components.weber_connect.select import (
    async_setup_entry as async_setup_select,
)

DEVICE_ID = "11" * 16
APPLIANCE_ID = "22" * 16

# 82.2 C, the SmokeBoost target a real SmokeFire reports.
SMOKE_BOOST_DC = 822
ENCODED_TARGET = b"\x36\x03"
NO_TEMPERATURE = b"\x00\x80"


def test_set_cook_mode_body_follows_the_negotiated_message_version() -> None:
    """Each format Weber shipped stays reachable by the appliances using it."""

    assert build_set_cook_mode_body(6, 1, SMOKE_BOOST_DC) == ENCODED_TARGET
    assert build_set_cook_mode_body(10, 2, SMOKE_BOOST_DC) == b"\x02" + ENCODED_TARGET
    assert build_set_cook_mode_body(11, 2, SMOKE_BOOST_DC) == (
        b"\x01\x01\x02\x02\x02" + ENCODED_TARGET
    )


def test_absent_target_uses_the_sentinel_rather_than_zero_degrees() -> None:
    """A missing target must never reach an appliance as a request for 0 C."""

    assert build_set_cook_mode_body(6, 1) == NO_TEMPERATURE
    assert build_set_cook_mode_body(10, 1) == b"\x01" + NO_TEMPERATURE
    # The tagged form omits the field entirely instead of sending the sentinel.
    assert build_set_cook_mode_body(11, 1) == b"\x01\x01\x01"


def test_set_cook_mode_body_rejects_an_unencodable_target() -> None:
    with pytest.raises(ValueError, match="signed 16-bit"):
        build_set_cook_mode_body(11, 1, 40000)


def test_cook_modes_cover_every_mode_the_appliance_can_report() -> None:
    assert COOK_MODES[11] == "pizza"
    assert COOK_MODES[12] == "clean"
    assert COOK_MODE_VALUES["grill"] == 1
    assert COOK_MODE_VALUES["smoke_boost"] == 2
    assert set(COOK_MODE_OPTIONS) == set(COOK_MODES.values())


class FakeHass:
    async def async_add_executor_job(self, target: object, *args: object) -> object:
        return target(*args)  # type: ignore[operator]


class FakeCloudClient:
    def __init__(self, config: object | None = None) -> None:
        self.config = config or SimpleNamespace(device_id=DEVICE_ID)
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)


async def test_command_refuses_to_open_a_second_socket_of_its_own() -> None:
    """Only the status loop connects, so a command on a dead socket must fail."""

    session = socket.WeberCloudSession(FakeHass(), FakeCloudClient(), APPLIANCE_ID)  # type: ignore[arg-type]
    with pytest.raises(socket.WeberCloudSocketError, match="not connected"):
        await session.async_send_command(0x0C, b"\x01")


async def test_command_sends_on_the_live_socket_and_polls_immediately() -> None:
    session = socket.WeberCloudSession(FakeHass(), FakeCloudClient(), APPLIANCE_ID)  # type: ignore[arg-type]
    connection = FakeConnection()
    session._connection = connection  # type: ignore[assignment]

    await session.async_send_command(0x0C, b"\x02" + ENCODED_TARGET)

    decoded = socket.decode_routed_message(connection.sent[0])
    assert decoded.type_value == 0x0C
    assert decoded.payload == b"\x02" + ENCODED_TARGET
    assert decoded.target_id == APPLIANCE_ID
    assert session._wake.is_set()


def _entry(hass: object, message_version: int | None) -> SimpleNamespace:
    data = {
        "address": "AA:BB:CC:DD:EE:FF",
        CONF_COMPANION_ID: DEVICE_ID,
        CONF_CLOUD_PASSWORD: "cloud-password",
        CONF_APPLIANCE_ID: APPLIANCE_ID,
    }
    if message_version is not None:
        data[CONF_MESSAGE_VERSION] = message_version  # type: ignore[assignment]
    return SimpleNamespace(
        data=data,
        options={},
        entry_id="test-entry",
        unique_id="AA:BB:CC:DD:EE:FF",
        title="SmokeFire",
        pref_disable_polling=False,
        async_create_background_task=MagicMock(),
        async_on_unload=MagicMock(),
    )


def _coordinator(hass: object, message_version: int | None) -> WeberCoordinator:
    with (
        patch.object(coordinator_module, "WeberCloudClient", FakeCloudClient),
        patch.object(coordinator_module, "WeberCloudSession", return_value=MagicMock()),
    ):
        return WeberCoordinator(hass, _entry(hass, message_version))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("message_version", "expected"),
    [(10, b"\x02" + ENCODED_TARGET), (11, b"\x01\x01\x02\x02\x02" + ENCODED_TARGET)],
)
async def test_coordinator_encodes_for_the_version_the_appliance_agreed(
    hass: object,
    message_version: int,
    expected: bytes,
) -> None:
    coordinator = _coordinator(hass, message_version)
    coordinator.cloud_session.async_send_command = AsyncMock()

    await coordinator.async_set_cook_mode(2, SMOKE_BOOST_DC)

    coordinator.cloud_session.async_send_command.assert_awaited_once_with(0x0C, expected)


def test_coordinator_defaults_to_the_newest_format_without_a_stored_version(
    hass: object,
) -> None:
    assert _coordinator(hass, None).message_version == 11


def _entity_entry(coordinator: object) -> SimpleNamespace:
    return SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        unique_id="AA:BB:CC:DD:EE:FF",
        entry_id="entry",
        title="SmokeFire",
        data={"address": "AA:BB:CC:DD:EE:FF"},
        async_on_unload=MagicMock(),
    )


def _fake_coordinator(data: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        data=data,
        last_update_success=True,
        async_add_listener=lambda listener: listener,
        async_set_cook_mode=AsyncMock(),
    )


async def test_controls_appear_only_once_the_appliance_reports_them(hass: object) -> None:
    """A hub that never reports a target or mode must not gain dead controls."""

    listeners: list[object] = []
    coordinator = _fake_coordinator({"target_grill_temperature": None, "cook_mode": None})
    coordinator.async_add_listener = lambda listener: listeners.append(listener) or MagicMock()
    entry = _entity_entry(coordinator)

    add_number = MagicMock()
    add_select = MagicMock()
    await async_setup_number(hass, entry, add_number)  # type: ignore[arg-type]
    await async_setup_select(hass, entry, add_select)  # type: ignore[arg-type]
    add_number.assert_not_called()
    add_select.assert_not_called()

    coordinator.data = {"target_grill_temperature": 82.2, "cook_mode": "smoke_boost"}
    for listener in listeners:
        listener()
    assert add_number.call_count == 1
    assert add_select.call_count == 1

    # A second report must not add a duplicate of either control.
    for listener in listeners:
        listener()
    assert add_number.call_count == 1
    assert add_select.call_count == 1


async def test_target_control_resends_the_reported_cook_mode(hass: object) -> None:
    coordinator = _fake_coordinator({"target_grill_temperature": 82.2, "cook_mode": "smoke_boost"})
    number = WeberTargetTemperatureNumber(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    assert number.native_value == 82.2
    await number.async_set_native_value(120.0)
    coordinator.async_set_cook_mode.assert_awaited_once_with(2, 1200)


@pytest.mark.parametrize("cook_mode", [None, "unknown", 5, "not-a-mode"])
async def test_target_control_refuses_to_light_an_idle_appliance(
    hass: object,
    cook_mode: object,
) -> None:
    """Substituting a cooking mode would turn a temperature edit into ignition."""

    coordinator = _fake_coordinator({"target_grill_temperature": 82.2, "cook_mode": cook_mode})
    number = WeberTargetTemperatureNumber(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    with pytest.raises(HomeAssistantError, match="cook mode"):
        await number.async_set_native_value(120.0)
    coordinator.async_set_cook_mode.assert_not_awaited()


async def test_target_control_reports_no_value_for_malformed_telemetry(hass: object) -> None:
    coordinator = _fake_coordinator({"target_grill_temperature": "hot"})
    number = WeberTargetTemperatureNumber(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]
    assert number.native_value is None


async def test_cook_mode_control_keeps_the_reported_target(hass: object) -> None:
    coordinator = _fake_coordinator({"cook_mode": "smoke_boost", "target_grill_temperature": 82.2})
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    assert select.current_option == "smoke_boost"
    await select.async_select_option("grill")
    coordinator.async_set_cook_mode.assert_awaited_once_with(1, SMOKE_BOOST_DC)


async def test_cook_mode_control_sends_no_target_when_none_is_reported(hass: object) -> None:
    coordinator = _fake_coordinator({"cook_mode": "grill", "target_grill_temperature": None})
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    await select.async_select_option("warm")
    coordinator.async_set_cook_mode.assert_awaited_once_with(10, None)


@pytest.mark.parametrize("reported", [None, 3, "retired_mode"])
async def test_cook_mode_control_reports_no_option_for_an_unknown_mode(
    hass: object,
    reported: object,
) -> None:
    coordinator = _fake_coordinator({"cook_mode": reported})
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]
    assert select.current_option is None


async def test_cook_mode_control_rejects_an_option_the_appliance_cannot_report(
    hass: object,
) -> None:
    coordinator = _fake_coordinator({"cook_mode": "grill"})
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    with pytest.raises(HomeAssistantError, match="not a cook mode"):
        await select.async_select_option("rotisserie")
    coordinator.async_set_cook_mode.assert_not_awaited()
