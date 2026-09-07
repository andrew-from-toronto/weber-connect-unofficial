"""Cook mode control for Weber Connect."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import WeberCoordinator
from .entity import WeberEntity
from .models import WeberRuntimeData
from .saber_frames import COOK_MODE_VALUES, COOK_MODES

# Offered only while an appliance has not reported its capability word. Listing
# every mode is the honest fallback there: the alternative is hiding modes a
# grill really has because this integration never heard which ones they are.
ALL_COOK_MODES = [COOK_MODES[value] for value in sorted(COOK_MODES)]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the cook mode control."""

    runtime: WeberRuntimeData = entry.runtime_data
    coordinator = runtime.coordinator
    added = False

    def _async_add_cook_mode() -> None:
        nonlocal added
        if added or coordinator.data.get("cook_mode") is None:
            return
        added = True
        async_add_entities([WeberCookModeSelect(coordinator, entry)])

    _async_add_cook_mode()
    entry.async_on_unload(coordinator.async_add_listener(_async_add_cook_mode))


class WeberCookModeSelect(WeberEntity, SelectEntity):
    """Choose how an appliance cooks."""

    _attr_translation_key = "cook_mode_control"

    def __init__(self, coordinator: WeberCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "cook_mode_control")

    @property
    def options(self) -> list[str]:
        """List only the modes the appliance says it can cook in."""

        reported = self.coordinator.data.get("supported_cook_modes")
        if isinstance(reported, list):
            supported = [mode for mode in reported if mode in COOK_MODE_VALUES]
            if supported:
                return supported
        return list(ALL_COOK_MODES)

    @property
    def current_option(self) -> str | None:
        """Report the running mode, or nothing when it is not selectable.

        An idle appliance reports "unknown", which is a state rather than a mode
        anyone can choose, so it stays out of the option list and reads as no
        current option instead.
        """

        value = self.coordinator.data.get("cook_mode")
        return value if isinstance(value, str) and value in self.options else None

    async def async_select_option(self, option: str) -> None:
        """Send the chosen mode, keeping the target the appliance reports.

        Changing the mode alone would otherwise clear the target, because the
        appliance reads one absent field as "no temperature" rather than as
        "leave the existing value alone".
        """

        if option not in self.options:
            raise HomeAssistantError(f"This appliance does not support the {option} cook mode.")
        target = self.coordinator.data.get("target_grill_temperature")
        target_deci_celsius = (
            round(float(target) * 10) if isinstance(target, (int, float)) else None
        )
        await self.coordinator.async_set_cook_mode(COOK_MODE_VALUES[option], target_deci_celsius)
