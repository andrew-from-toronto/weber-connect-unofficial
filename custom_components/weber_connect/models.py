"""Runtime models for the unofficial Weber Connect integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CompanionIdentity:
    """Private identity paired with a Weber hub."""

    companion_id: str
    public_key: str


@dataclass(frozen=True, slots=True)
class PairingResult:
    """Result of one physically confirmed pairing operation."""

    message_version: int
    appliance_id: str
    # The appliance's half of the material a local secure session is derived
    # from. It is offered exactly once, in the pairing response, so an entry
    # created without it can never command the appliance locally until the user
    # pairs again. Empty for entries that predate local control.
    appliance_public_key: str = ""


@dataclass(slots=True)
class WeberRuntimeData:
    """Objects owned by one Home Assistant config entry."""

    coordinator: Any
