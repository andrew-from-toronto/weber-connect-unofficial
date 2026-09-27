"""Probe target controls for Weber Connect."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import WeberCoordinator
from .entity import WeberEntity, known_probe_numbers
from .models import WeberRuntimeData


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
        WeberClearProbeTargetButton(coordinator, entry, number)
        for number in sorted(known_probe_numbers(hass, entry))
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
