"""Probe target controls for Weber Connect."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import WeberCoordinator
from .entity import WeberEntity, known_probe_numbers
from .models import WeberRuntimeData

# CookMode.NONE in the app; with no target this is ShutDownGrillAction.
COOK_MODE_NONE = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up one clear-target button per probe, on a Bluetooth entry only."""

    runtime: WeberRuntimeData = entry.runtime_data
    coordinator = runtime.coordinator
    if getattr(coordinator, "source", None) != "bluetooth":
        return
    async_add_entities(
        [
            WeberShutdownButton(coordinator, entry),
            *(
                WeberClearProbeTargetButton(coordinator, entry, number)
                for number in sorted(known_probe_numbers(hass, entry))
            ),
        ]
    )


class WeberClearProbeTargetButton(WeberEntity, ButtonEntity):
    """End the target program running on one wired probe."""

    _attr_translation_key = "probe_target_clear"

    def __init__(self, coordinator: WeberCoordinator, entry: ConfigEntry, number: int) -> None:
        super().__init__(coordinator, entry, f"probe_{number}_target_clear")
        self._number = number
        self._attr_translation_placeholders = {"number": str(number)}

    async def async_press(self) -> None:
        await self.coordinator.async_clear_probe_target(self._number)


class WeberShutdownButton(WeberEntity, ButtonEntity):
    """Shut a lit grill down the way the app does: its own cool-down, not a reboot.

    ShutDownGrillAction in the app is one set-cook-mode with mode NONE and no target. The appliance
    command next to it (RESTART) is a reboot and is deliberately not what this sends. Refused unless the
    grill reports itself lit: mode NONE sent to an idle grill is behaviour nobody has measured.
    """

    _attr_translation_key = "shutdown"

    def __init__(self, coordinator: WeberCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "shutdown")

    async def async_press(self) -> None:
        if self.coordinator.data.get("device_state") != "active":
            raise HomeAssistantError("The grill is not lit, so there is nothing to shut down.")
        await self.coordinator.async_set_cook_mode(COOK_MODE_NONE)
