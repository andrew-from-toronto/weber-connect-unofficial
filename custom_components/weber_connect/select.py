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

# Ordered by the appliance's own byte values so the list reads the same way in
# every language. "unknown" is offered because an idle appliance reports it, and
# Home Assistant requires the current option to be selectable.
COOK_MODE_OPTIONS = [COOK_MODES[value] for value in sorted(COOK_MODES)]


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
    _attr_options = COOK_MODE_OPTIONS

    def __init__(self, coordinator: WeberCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "cook_mode_control")

    @property
    def current_option(self) -> str | None:
        value = self.coordinator.data.get("cook_mode")
        return value if isinstance(value, str) and value in COOK_MODE_OPTIONS else None

    async def async_select_option(self, option: str) -> None:
        """Send the chosen mode, keeping the target the appliance reports.

        Changing the mode alone would otherwise clear the target, because the
        appliance reads one absent field as "no temperature" rather than as
        "leave the existing value alone".
        """

        cook_mode_value = COOK_MODE_VALUES.get(option)
        if cook_mode_value is None:
            raise HomeAssistantError(f"{option} is not a cook mode this appliance reports.")
        target = self.coordinator.data.get("target_grill_temperature")
        target_deci_celsius = (
            round(float(target) * 10) if isinstance(target, (int, float)) else None
        )
        await self.coordinator.async_set_cook_mode(cook_mode_value, target_deci_celsius)
