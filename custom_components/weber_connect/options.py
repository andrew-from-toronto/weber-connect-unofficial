"""Typed user options for Weber Connect Unofficial."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from .const import (
    CONF_CONNECTION,
    CONF_CONNECTION_MODE,
    CONF_PROBE_NAME_PREFIX,
    CONF_PROBES,
    CONF_USE_BLUETOOTH,
)


class ConnectionMode(StrEnum):
    """How Home Assistant should receive live Weber data."""

    PHONE_AND_HOME_ASSISTANT = "phone_and_home_assistant"


@dataclass(frozen=True, slots=True)
class WeberOptions:
    """Validated effective options with product defaults."""

    connection_mode: ConnectionMode = ConnectionMode.PHONE_AND_HOME_ASSISTANT
    # Only meaningful for an entry that stored session material when it was
    # paired. It lets the owner fall back to cloud reads without discarding
    # those secrets - the local link is unproven hardware territory, and the
    # alternative way back is deleting the entry, which is what breaks
    # dashboards. It can never turn Bluetooth on for an entry without secrets.
    use_bluetooth: bool = True
    probe_names: tuple[str, str, str, str] = ("", "", "", "")

    @property
    def cloud_enabled(self) -> bool:
        """Whether online reads are enabled for phone + Home Assistant use."""

        return self.connection_mode is ConnectionMode.PHONE_AND_HOME_ASSISTANT

    def probe_name(self, number: int) -> str:
        """Return a cleaned optional nickname for one physical probe slot."""

        if not 1 <= number <= 4:
            raise ValueError("Probe number must be between 1 and 4.")
        return self.probe_names[number - 1]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> WeberOptions:
        """Build effective options from Home Assistant's stored mapping."""

        connection = _mapping(raw.get(CONF_CONNECTION))
        probes = _mapping(raw.get(CONF_PROBES))
        try:
            mode = ConnectionMode(
                connection.get(
                    CONF_CONNECTION_MODE,
                    ConnectionMode.PHONE_AND_HOME_ASSISTANT,
                )
            )
        except ValueError:
            # Versions through 3.1.2 offered an unauthenticated local telemetry
            # mode. Fail closed by migrating that retired value to cloud reads.
            mode = ConnectionMode.PHONE_AND_HOME_ASSISTANT

        names = (
            _probe_name(probes, 1),
            _probe_name(probes, 2),
            _probe_name(probes, 3),
            _probe_name(probes, 4),
        )
        return cls(
            connection_mode=mode,
            use_bluetooth=bool(connection.get(CONF_USE_BLUETOOTH, True)),
            probe_names=names,
        )

    def as_dict(self) -> dict[str, Any]:
        """Serialize options into native Home Assistant form sections."""

        return {
            CONF_CONNECTION: {
                CONF_CONNECTION_MODE: self.connection_mode.value,
                CONF_USE_BLUETOOTH: self.use_bluetooth,
            },
            CONF_PROBES: {
                f"{CONF_PROBE_NAME_PREFIX}{number}": self.probe_name(number)
                for number in range(1, 5)
            },
        }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _probe_name(probes: Mapping[str, Any], number: int) -> str:
    return str(probes.get(f"{CONF_PROBE_NAME_PREFIX}{number}", "")).strip()[:40]
