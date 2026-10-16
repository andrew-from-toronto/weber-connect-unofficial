"""Unofficial native Home Assistant integration for Weber Connect."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_APPLIANCE_ID, CONF_PAIRING_KEY_REF, CONF_TRANSPORT_FAMILY, PLATFORMS
from .coordinator import WeberCoordinator
from .models import WeberRuntimeData
from .pairing_storage import PairingKeyStore, SaberSessionCredentials
from .silabs_secure import SiLabsSecurityError
from .transport_family import TransportFamily

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a Weber hub from a config entry."""

    coordinator = WeberCoordinator(
        hass, entry, saber_session=await _async_load_saber_session(hass, entry)
    )
    # A sleeping grill or a busy Bluetooth proxy must never delay Home
    # Assistant startup. Publish a complete, honest initial state immediately;
    # the entry-scoped background loop performs the first transport read after
    # the entity platforms are ready.
    coordinator.async_set_updated_data(coordinator.initial_state())
    entry.runtime_data = WeberRuntimeData(coordinator=coordinator)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    coordinator.async_start()
    return True


async def _async_load_saber_session(
    hass: HomeAssistant, entry: ConfigEntry
) -> SaberSessionCredentials | None:
    """Load a Saber entry's local session keys; without them the entry reads the cloud."""

    reference = entry.data.get(CONF_PAIRING_KEY_REF)
    family = entry.data.get(CONF_TRANSPORT_FAMILY, TransportFamily.SABER)
    if reference is None or family != TransportFamily.SABER:
        return None
    try:
        return await PairingKeyStore(hass, reference).async_load_saber(
            str(entry.data[CONF_APPLIANCE_ID])
        )
    except SiLabsSecurityError:
        _LOGGER.warning("The stored Bluetooth pairing is unusable; reading through Weber Cloud.")
        return None


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Weber hub and close its cloud connection."""

    runtime: WeberRuntimeData = entry.runtime_data
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await runtime.coordinator.async_close()
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove the private pairing record only when its entry is deleted."""

    reference = entry.data.get(CONF_PAIRING_KEY_REF)
    if reference is not None:
        await PairingKeyStore(hass, reference).async_remove()
