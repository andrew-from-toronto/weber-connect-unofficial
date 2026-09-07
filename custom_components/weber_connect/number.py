"""Target temperature control for Weber Connect."""

from __future__ import annotations

from homeassistant.components.number import NumberDeviceClass, NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import WeberCoordinator
from .entity import WeberEntity
from .models import WeberRuntimeData
from .saber_frames import COOK_MODE_VALUES

# Weber reports a per-model target range only in the appliance capabilities
# frame, which this integration does not decode. Bound the control widely and
# let the appliance refuse what it cannot do, rather than inventing limits that
# would be wrong for some other grill.
MIN_TARGET_CELSIUS = 30.0
MAX_TARGET_CELSIUS = 320.0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the target temperature control."""

    runtime: WeberRuntimeData = entry.runtime_data
    coordinator = runtime.coordinator
    added = False

    def _async_add_target() -> None:
        nonlocal added
        if added or coordinator.data.get("target_grill_temperature") is None:
            return
        added = True
        async_add_entities([WeberTargetTemperatureNumber(coordinator, entry)])

    _async_add_target()
    entry.async_on_unload(coordinator.async_add_listener(_async_add_target))


class WeberTargetTemperatureNumber(WeberEntity, NumberEntity):
    """Set the temperature an appliance is cooking towards."""

    _attr_translation_key = "target_temperature"
    _attr_device_class = NumberDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_native_min_value = MIN_TARGET_CELSIUS
    _attr_native_max_value = MAX_TARGET_CELSIUS
    _attr_native_step = 1.0
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator: WeberCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "target_temperature")

    @property
    def native_value(self) -> float | None:
        value = self.coordinator.data.get("target_grill_temperature")
        return float(value) if isinstance(value, (int, float)) else None

    async def async_set_native_value(self, value: float) -> None:
        """Resend the reported cook mode with a new target.

        Every encoding carries the cook mode, so a target change has to state
        one. Refuse rather than substitute a mode: on an idle grill, choosing a
        cooking mode here would light it in response to a temperature edit.
        """

        cook_mode = self.coordinator.data.get("cook_mode")
        cook_mode_value = COOK_MODE_VALUES.get(cook_mode) if isinstance(cook_mode, str) else None
        if not cook_mode_value:
            raise HomeAssistantError(
                "The appliance is not reporting a cook mode. Choose a cook mode first, "
                "then set the target temperature."
            )
        await self.coordinator.async_set_cook_mode(cook_mode_value, round(value * 10))
