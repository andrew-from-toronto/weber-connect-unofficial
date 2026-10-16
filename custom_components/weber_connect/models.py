"""Runtime models for the unofficial Weber Connect integration."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    # created without it can never use the local link until the user pairs
    # again. Empty for entries that predate local control. Keyword-only so
    # SiLabsPairingResult can keep extending this with required fields.
    appliance_public_key: str = field(default="", kw_only=True)


@dataclass(frozen=True, slots=True)
class BluetoothFrameSummary:
    """Structural evidence only; never retain packet bytes or identities."""

    received_bytes: int
    transport_present: bool
    transport_length_ok: bool | None
    transport_has_extra: bool
    envelope_present: bool
    envelope_crc_ok: bool | None
    envelope_tail_ok: bool | None


@dataclass(slots=True)
class WeberRuntimeData:
    """Objects owned by one Home Assistant config entry."""

    coordinator: Any
