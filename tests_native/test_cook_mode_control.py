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
    parse_appliance_capabilities_payload,
    supported_cook_modes,
)
from custom_components.weber_connect.select import (
    ALL_COOK_MODES,
    WeberCookModeSelect,
)
from custom_components.weber_connect.select import (
    async_setup_entry as async_setup_select,
)
from custom_components.weber_connect.state import normalize_state

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
    assert set(ALL_COOK_MODES) == set(COOK_MODES.values())


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

    with pytest.raises(HomeAssistantError, match="does not support"):
        await select.async_select_option("rotisserie")
    coordinator.async_set_cook_mode.assert_not_awaited()


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def spec(spec_id: int, min_dc: int, max_dc: int, default_dc: int, step_dc: int) -> bytes:
    return (
        tlv(1, min_dc.to_bytes(2, "little", signed=True))
        + tlv(2, max_dc.to_bytes(2, "little", signed=True))
        + tlv(3, default_dc.to_bytes(2, "little", signed=True))
        + tlv(4, bytes([step_dc]))
        + tlv(5, bytes([spec_id]))
    )


# Bits 5 and 6: grill and smoke boost, the two modes a SmokeFire cooks in.
SMOKEFIRE_BITS = (1 << 5) | (1 << 6)
CAPABILITIES = (
    tlv(1, bytes([4]))
    + tlv(2, bytes([0]))
    + tlv(3, b"SMOKEFIRE-EX4")
    + tlv(21, SMOKEFIRE_BITS.to_bytes(4, "little"))
    + tlv(14, spec(1, 930, 3160, 1770, 5))
    + tlv(14, spec(2, 820, 1600, 820, 5))
    + tlv(13, spec(0, 0, 1000, 600, 5))
    + tlv(24, bytes([2]))
)


def test_capabilities_frame_reports_probes_modes_and_ranges() -> None:
    parsed = parse_appliance_capabilities_payload(CAPABILITIES)
    assert parsed["sku"] == "SMOKEFIRE-EX4"
    assert parsed["probe_count"] == 4
    assert parsed["max_wireless_probes"] == 2
    assert parsed["capability_bits"] == SMOKEFIRE_BITS
    assert [row["id"] for row in parsed["cavity_temperature_specs"]] == [1, 2]
    assert parsed["cavity_temperature_specs"][0] == {
        "id": 1,
        "min_dc": 930,
        "max_dc": 3160,
        "default_dc": 1770,
        "step_dc": 5,
    }
    assert len(parsed["probe_temperature_specs"]) == 1


def test_a_truncated_specification_is_dropped_rather_than_half_read() -> None:
    """A partial range must never become a limit a control enforces."""

    parsed = parse_appliance_capabilities_payload(tlv(14, tlv(1, b"\x01\x02")))
    assert parsed["cavity_temperature_specs"] == []
    assert parsed["capability_bits"] is None


def test_supported_cook_modes_follow_the_capability_word() -> None:
    assert supported_cook_modes(SMOKEFIRE_BITS) == ("grill", "smoke_boost")
    assert supported_cook_modes(None) == ()
    assert supported_cook_modes(0) == ()


def test_state_exposes_the_range_belonging_to_the_running_mode() -> None:
    state = normalize_state(
        {"cook_mode": "smoke_boost", **parse_appliance_capabilities_payload(CAPABILITIES)},
        source="cloud",
        connected=True,
    )
    assert state["supported_cook_modes"] == ["grill", "smoke_boost"]
    assert state["target_min_temperature"] == 82.0
    assert state["target_max_temperature"] == 160.0
    assert state["supports_ignition_request"] is False
    assert state["requires_target_on_device_first"] is False


def test_state_widens_to_every_range_while_no_mode_is_running() -> None:
    """An idle grill must not inherit the limits of an arbitrary mode."""

    state = normalize_state(
        parse_appliance_capabilities_payload(CAPABILITIES),
        source="cloud",
        connected=True,
    )
    assert state["target_min_temperature"] == 82.0
    assert state["target_max_temperature"] == 316.0


def test_state_reports_no_limits_when_the_appliance_sends_no_capabilities() -> None:
    state = normalize_state({"cook_mode": "grill"}, source="cloud", connected=True)
    assert state["supported_cook_modes"] == []
    assert state["target_min_temperature"] is None
    assert state["supports_ignition_request"] is None


async def test_target_control_uses_the_reported_range(hass: object) -> None:
    coordinator = _fake_coordinator(
        {
            "target_grill_temperature": 82.2,
            "cook_mode": "smoke_boost",
            "target_min_temperature": 82.0,
            "target_max_temperature": 160.0,
            "target_step": 0.5,
        }
    )
    number = WeberTargetTemperatureNumber(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    assert number.native_min_value == 82.0
    assert number.native_max_value == 160.0
    assert number.native_step == 0.5

    with pytest.raises(HomeAssistantError, match="outside"):
        await number.async_set_native_value(200.0)
    coordinator.async_set_cook_mode.assert_not_awaited()


async def test_target_control_falls_back_when_no_range_is_reported(hass: object) -> None:
    coordinator = _fake_coordinator(
        {"target_grill_temperature": 82.2, "cook_mode": "grill", "target_step": 0}
    )
    number = WeberTargetTemperatureNumber(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    assert number.native_min_value == 30.0
    assert number.native_max_value == 320.0
    # A reported step of zero is unusable as an increment.
    assert number.native_step == 1.0


async def test_target_control_honours_set_on_device_first(hass: object) -> None:
    coordinator = _fake_coordinator(
        {
            "target_grill_temperature": None,
            "cook_mode": "grill",
            "requires_target_on_device_first": True,
        }
    )
    number = WeberTargetTemperatureNumber(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    with pytest.raises(HomeAssistantError, match="on the grill"):
        await number.async_set_native_value(120.0)
    coordinator.async_set_cook_mode.assert_not_awaited()


async def test_cook_mode_control_offers_only_supported_modes(hass: object) -> None:
    coordinator = _fake_coordinator(
        {"cook_mode": "grill", "supported_cook_modes": ["grill", "smoke_boost"]}
    )
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]

    assert select.options == ["grill", "smoke_boost"]
    with pytest.raises(HomeAssistantError, match="does not support"):
        await select.async_select_option("sear")


@pytest.mark.parametrize("reported", [None, [], ["not-a-mode"]])
async def test_cook_mode_control_offers_everything_until_capabilities_arrive(
    hass: object,
    reported: object,
) -> None:
    """Hiding modes because none were reported would lose real grill features."""

    coordinator = _fake_coordinator({"cook_mode": "grill", "supported_cook_modes": reported})
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]
    assert select.options == ALL_COOK_MODES


async def test_idle_mode_is_reported_but_not_offered(hass: object) -> None:
    coordinator = _fake_coordinator(
        {"cook_mode": "unknown", "supported_cook_modes": ["grill", "smoke_boost"]}
    )
    select = WeberCookModeSelect(coordinator, _entity_entry(coordinator))  # type: ignore[arg-type]
    assert "unknown" not in select.options
    assert select.current_option is None


@pytest.mark.parametrize(
    "specs",
    ["not-a-list", [None], [{"id": 1}], [{"id": 1, "min_dc": "cold"}]],
)
def test_malformed_ranges_never_become_control_limits(specs: object) -> None:
    """A half-read range would silently cap a grill below what it can cook."""

    state = normalize_state(
        {"cook_mode": "grill", "cavity_temperature_specs": specs},
        source="cloud",
        connected=True,
    )
    assert state["target_min_temperature"] is None
    assert state["target_max_temperature"] is None
    assert state["target_step"] is None


async def test_capabilities_survive_a_reconnect() -> None:
    """Hardware facts must outlive the cook status they arrived alongside."""

    session = socket.WeberCloudSession(FakeHass(), FakeCloudClient(), APPLIANCE_ID)  # type: ignore[arg-type]
    session._capabilities = {"capability_bits": SMOKEFIRE_BITS}
    session._appliance_status = {"device_state": "active", "cook_mode": "grill"}

    await session._async_close_connection()

    assert session._capabilities == {"capability_bits": SMOKEFIRE_BITS}
    assert "cook_mode" not in session._appliance_status
    assert session._appliance_status["device_state"] == "active"
