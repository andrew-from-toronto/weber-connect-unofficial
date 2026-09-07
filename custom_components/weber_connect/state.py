"""Normalize local and cloud Weber status into one entity-friendly model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .saber_frames import (
    COOK_MODE_VALUES,
    IGNITION_REQUEST_CAPABILITY_BIT,
    SHUTDOWN_CAPABILITY_BIT,
    TARGET_ON_DEVICE_FIRST_CAPABILITY_BIT,
    has_capability,
    supported_cook_modes,
)

ACTIVE_SESSION_STATES = {"PRIMED", "READY", "ACTIVE", "PAUSED", "ACTIVE_FIXED", "PREHEAT"}
_SPEC_FIELDS = ("id", "min_dc", "max_dc", "default_dc", "step_dc")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _percent(value: Any) -> int | None:
    if type(value) is int and 0 <= value <= 100:
        return value
    return None


def _number(value: Any) -> int | float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return None


def _intensity(value: Any) -> int | None:
    if type(value) is int and 1 <= value <= 10:
        return value
    return None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _cavity_spec(specs: Any, cook_mode: Any) -> dict[str, int] | None:
    """Return the range covering the current mode, or the widest reported one.

    An appliance reports one cavity range per cook mode it supports. Falling
    back to the widest range keeps the control usable while a grill is idle and
    reporting no mode, rather than presenting limits belonging to another mode.
    """

    rows: list[dict[str, int]] = []
    for row in specs if isinstance(specs, list) else []:
        if isinstance(row, dict) and all(type(row.get(field)) is int for field in _SPEC_FIELDS):
            rows.append({field: int(row[field]) for field in _SPEC_FIELDS})
    if not rows:
        return None
    mode_value = COOK_MODE_VALUES.get(cook_mode) if isinstance(cook_mode, str) else None
    for row in rows:
        if row["id"] == mode_value:
            return row
    return {
        "id": -1,
        "min_dc": min(row["min_dc"] for row in rows),
        "max_dc": max(row["max_dc"] for row in rows),
        "default_dc": rows[0]["default_dc"],
        "step_dc": min(row["step_dc"] for row in rows),
    }


def _spec_celsius(spec: dict[str, int] | None, key: str) -> float | None:
    """Convert one deci-Celsius field of a reported range to Celsius."""

    if spec is None:
        return None
    return round(spec[key] / 10.0, 1)


def normalize_state(
    status: dict[str, Any] | None,
    *,
    source: str,
    connected: bool,
    last_successful_update: str | None = None,
) -> dict[str, Any]:
    """Return capability-driven appliance telemetry in an entity-friendly shape."""

    raw = status or {}

    # Fall back to display temp if actual temp isn't broadcast
    grill_temp = raw.get("actual_cavity_temp_c")
    if grill_temp is None:
        grill_temp = raw.get("display_cavity_temp_c")

    state: dict[str, Any] = {
        "updated_at": _utc_now(),
        "connected": connected,
        "reading_status": "receiving"
        if connected
        else ("connection_lost" if last_successful_update else "waiting"),
        "source": source,
        "last_successful_update": last_successful_update,
        "grill_temperature": grill_temp,
        "target_grill_temperature": _number(raw.get("target_cavity_temp_c")),
        "cook_mode": _text(raw.get("cook_mode")),
        "cook_intensity": _intensity(raw.get("simple_intensity")),
        "battery_level": _percent(raw.get("battery_level")),
        "is_charging": raw.get("is_charging") if type(raw.get("is_charging")) is bool else None,
        "wifi_signal_strength": (
            raw.get("wifi_signal_strength")
            if type(raw.get("wifi_signal_strength")) is int
            else None
        ),
        "wifi_connection_status": _text(raw.get("wifi_connection_status")),
        "cloud_connection_status": _text(raw.get("cloud_connection_status")),
        "device_state": _text(raw.get("device_state")),
        "fuel_percent": _percent(raw.get("fuel_percent")),
        "fuel_level": _text(raw.get("fuel_level")),
        "software_version": _text(raw.get("software_version")),
        "hardware_version": _text(raw.get("hardware_version")),
    }
    probes = raw.get("probes")
    if not isinstance(probes, list):
        probes = []
    probes_by_number: dict[int, dict[str, Any]] = {}
    for row in probes:
        if not isinstance(row, dict):
            continue
        number = row.get("probe_number")
        if type(number) is int and 1 <= number <= 4:
            probes_by_number.setdefault(number, row)
    state["reported_probe_numbers"] = tuple(sorted(probes_by_number))
    for number in range(1, 5):
        probe = probes_by_number.get(number, {})
        state[f"probe_{number}_temperature"] = probe.get("probe_temp_c")
        state[f"probe_{number}_ambient_temperature"] = probe.get("ambient_temp_c")
        state[f"probe_{number}_case_temperature"] = probe.get("case_temp_c")
        state[f"probe_{number}_battery"] = _percent(probe.get("battery_level"))
        state[f"probe_{number}_time_remaining"] = probe.get("time_remaining_s")
        state[f"probe_{number}_time_elapsed"] = probe.get("time_elapsed_s")
        state[f"probe_{number}_prompt_time_remaining"] = probe.get("prompt_time_remaining_s")
        state[f"probe_{number}_prompt_time_elapsed"] = probe.get("prompt_time_elapsed_s")
        state[f"probe_{number}_state"] = probe.get("state")
        state[f"probe_{number}_reading_status"] = (
            state["reading_status"]
            if not connected
            else "reading"
            if probe.get("probe_temp_c") is not None
            else "device_off"
            if raw.get("device_state") == "off"
            else "no_reading"
        )
        state[f"probe_{number}_type"] = probe.get("probe_type")
        state[f"probe_{number}_serial_number"] = probe.get("serial_number")
        state[f"probe_{number}_sku"] = probe.get("sku")

    timed_sessions = raw.get("timed_sessions")
    if not isinstance(timed_sessions, list):
        timed_sessions = []
    timed_by_number: dict[int, dict[str, Any]] = {}
    for row in timed_sessions:
        if not isinstance(row, dict):
            continue
        number = row.get("slot_number")
        if type(number) is int and 1 <= number <= 16:
            timed_by_number.setdefault(number, row)
    state["reported_timed_session_numbers"] = tuple(sorted(timed_by_number))
    for number, row in timed_by_number.items():
        state[f"timed_session_{number}_time_remaining"] = row.get("time_remaining_s")
        state[f"timed_session_{number}_time_elapsed"] = row.get("time_elapsed_s")
        state[f"timed_session_{number}_state"] = row.get("state")

    timers = raw.get("timers")
    if not isinstance(timers, list):
        timers = []
    timers_by_number: dict[int, dict[str, Any]] = {}
    for row in timers:
        if not isinstance(row, dict):
            continue
        number = row.get("slot_number")
        if type(number) is int and 1 <= number <= 16:
            timers_by_number.setdefault(number, row)
    state["reported_timer_numbers"] = tuple(sorted(timers_by_number))
    for number, row in timers_by_number.items():
        state[f"timer_{number}_time_remaining"] = row.get("time_remaining_s")
        state[f"timer_{number}_time_elapsed"] = row.get("time_elapsed_s")
        state[f"timer_{number}_state"] = row.get("state")

    burners = raw.get("burners")
    if not isinstance(burners, list):
        burners = []
    burners_by_number: dict[int, dict[str, Any]] = {}
    for row in burners:
        if not isinstance(row, dict):
            continue
        number = row.get("number")
        if type(number) is int and 1 <= number <= 16:
            burners_by_number.setdefault(number, row)
    state["reported_burner_numbers"] = tuple(sorted(burners_by_number))
    for number, row in burners_by_number.items():
        state[f"burner_{number}_state"] = row.get("state")
        state[f"burner_{number}_type"] = row.get("type")
        state[f"burner_{number}_target_intensity"] = _intensity(row.get("target_intensity"))
        state[f"burner_{number}_actual_intensity"] = _intensity(row.get("actual_intensity"))
        state[f"burner_{number}_flame_sensed"] = (
            row.get("flame_sensed") if type(row.get("flame_sensed")) is bool else None
        )
        state[f"burner_{number}_locked"] = (
            row.get("locked") if type(row.get("locked")) is bool else None
        )

    capability_bits = raw.get("capability_bits")
    if type(capability_bits) is not int:
        capability_bits = None
    state["capability_bits"] = capability_bits
    state["sku"] = _text(raw.get("sku"))
    state["supported_cook_modes"] = list(supported_cook_modes(capability_bits))
    state["supports_ignition_request"] = has_capability(
        capability_bits, IGNITION_REQUEST_CAPABILITY_BIT
    )
    state["supports_shutdown"] = has_capability(capability_bits, SHUTDOWN_CAPABILITY_BIT)
    state["requires_target_on_device_first"] = has_capability(
        capability_bits, TARGET_ON_DEVICE_FIRST_CAPABILITY_BIT
    )
    cavity_spec = _cavity_spec(raw.get("cavity_temperature_specs"), state["cook_mode"])
    state["target_min_temperature"] = _spec_celsius(cavity_spec, "min_dc")
    state["target_max_temperature"] = _spec_celsius(cavity_spec, "max_dc")
    state["target_default_temperature"] = _spec_celsius(cavity_spec, "default_dc")
    state["target_step"] = _spec_celsius(cavity_spec, "step_dc")

    all_session_states = [
        row.get("state")
        for row in [
            *probes_by_number.values(),
            *timed_by_number.values(),
            *timers_by_number.values(),
        ]
    ]
    burner_states = [row.get("state") for row in burners_by_number.values()]
    activity_reported = bool(all_session_states or burner_states or state["cook_mode"] is not None)
    state["cooking"] = (
        any(value in ACTIVE_SESSION_STATES for value in all_session_states)
        or any(value in {"on", "ignition_requested"} for value in burner_states)
        if activity_reported
        else None
    )
    return state
