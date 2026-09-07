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

# Used only until the appliance reports its own range in the capabilities
# frame. Wide on purpose: a narrower guess would block a grill this integration
# has never been run against.
FALLBACK_MIN_CELSIUS = 30.0
FALLBACK_MAX_CELSIUS = 320.0
FALLBACK_STEP_CELSIUS = 1.0


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
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator: WeberCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "target_temperature")

    def _reported(self, key: str, fallback: float) -> float:
        value = self.coordinator.data.get(key)
        return float(value) if isinstance(value, (int, float)) else fallback

    @property
    def native_min_value(self) -> float:
        return self._reported("target_min_temperature", FALLBACK_MIN_CELSIUS)

    @property
    def native_max_value(self) -> float:
        return self._reported("target_max_temperature", FALLBACK_MAX_CELSIUS)

    @property
    def native_step(self) -> float:
        step = self._reported("target_step", FALLBACK_STEP_CELSIUS)
        return step if step > 0 else FALLBACK_STEP_CELSIUS

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
        if self.coordinator.data.get("requires_target_on_device_first") and (
            self.native_value is None
        ):
            raise HomeAssistantError(
                "This appliance requires its target temperature to be set on the grill "
                "itself before it accepts one remotely."
            )
        # Home Assistant range-checks the number entity, but a service call can
        # still arrive out of range, and the appliance answers a bad target by
        # rejecting the whole command rather than clamping it.
        if not self.native_min_value <= value <= self.native_max_value:
            raise HomeAssistantError(
                f"{value} °C is outside the {self.native_min_value}-{self.native_max_value} °C "
                "range this appliance accepts."
            )
        await self.coordinator.async_set_cook_mode(cook_mode_value, round(value * 10))
