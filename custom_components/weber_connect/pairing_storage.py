"""Private, atomic Home Assistant storage for confirmed pairing keys."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .silabs_secure import SiLabsCipher, SiLabsSecurityError, SiLabsSigningKeys

_REFERENCE = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True, repr=False)
class SiLabsCredentials:
    """Secret pairing record; never place this object in diagnostics or config data."""

    companion_id: bytes
    appliance_id: bytes
    keys: SiLabsSigningKeys = field(repr=False)
    peer_public_key: bytes = field(repr=False)
    message_version: int

    def validate(self) -> None:
        if len(self.companion_id) != 16 or len(self.appliance_id) != 16:
            raise SiLabsSecurityError("Stored SiLabs identity is invalid.")
        if not 5 <= self.message_version <= 11:
            raise SiLabsSecurityError("Stored SiLabs message version is unsupported.")
        SiLabsCipher(self.keys, self.peer_public_key)


@dataclass(frozen=True, slots=True, repr=False)
class SaberSessionCredentials:
    """Secret Saber session record; never place this object in diagnostics or config data.

    The two 64-byte blobs a JOSL session is derived from (ADR 0004). The appliance
    offers its half exactly once, in the pairing response.
    """

    companion_id: bytes
    appliance_id: bytes
    companion_public_key: bytes = field(repr=False)
    appliance_public_key: bytes = field(repr=False)

    def validate(self) -> None:
        if len(self.companion_id) != 16 or len(self.appliance_id) != 16:
            raise SiLabsSecurityError("Stored Saber identity is invalid.")
        if len(self.companion_public_key) != 64 or len(self.appliance_public_key) != 64:
            raise SiLabsSecurityError("Stored Saber session material is invalid.")


class PairingKeyStore:
    """One private (0600) atomic storage file per companion, outside config entries.

    This uses Home Assistant's private-file protection, not an OS keychain or
    encrypted-at-rest guarantee. Backups must be protected like other HA secrets.
    """

    def __init__(self, hass: HomeAssistant, reference: str) -> None:
        if _REFERENCE.fullmatch(reference) is None:
            raise SiLabsSecurityError("Pairing storage reference is invalid.")
        self.reference = reference
        self._store = Store[dict[str, Any]](
            hass, 1, f"weber_connect.pairing.{reference}", private=True, atomic_writes=True
        )

    async def async_save(self, record: SiLabsCredentials | SaberSessionCredentials) -> None:
        record.validate()
        if record.companion_id.hex() != self.reference:
            raise SiLabsSecurityError("Pairing storage identity does not match its reference.")
        if isinstance(record, SaberSessionCredentials):
            await self._store.async_save(
                {
                    "family": "saber",
                    "companion_id": record.companion_id.hex(),
                    "appliance_id": record.appliance_id.hex(),
                    "companion_public_key": record.companion_public_key.hex(),
                    "appliance_public_key": record.appliance_public_key.hex(),
                }
            )
            return
        await self._store.async_save(
            {
                "companion_id": record.companion_id.hex(),
                "appliance_id": record.appliance_id.hex(),
                "signing_scalar": record.keys.private_scalar.hex(),
                "peer_point": record.peer_public_key.hex(),
                "message_version": record.message_version,
            }
        )

    async def async_load(self, appliance_id: str) -> SiLabsCredentials:
        data = await self._store.async_load()
        try:
            if data is None:
                raise ValueError("Missing record")
            record = SiLabsCredentials(
                bytes.fromhex(data["companion_id"]),
                bytes.fromhex(data["appliance_id"]),
                SiLabsSigningKeys.from_private_scalar(bytes.fromhex(data["signing_scalar"])),
                bytes.fromhex(data["peer_point"]),
                int(data["message_version"]),
            )
            record.validate()
            if (
                record.companion_id.hex() != self.reference
                or record.appliance_id.hex() != appliance_id
            ):
                raise ValueError("Identity mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise SiLabsSecurityError("Stored SiLabs pairing is missing or invalid.") from exc
        return record

    async def async_load_saber(self, appliance_id: str) -> SaberSessionCredentials:
        data = await self._store.async_load()
        try:
            if data is None or data.get("family") != "saber":
                raise ValueError("Missing record")
            record = SaberSessionCredentials(
                bytes.fromhex(data["companion_id"]),
                bytes.fromhex(data["appliance_id"]),
                bytes.fromhex(data["companion_public_key"]),
                bytes.fromhex(data["appliance_public_key"]),
            )
            record.validate()
            if (
                record.companion_id.hex() != self.reference
                or record.appliance_id.hex() != appliance_id
            ):
                raise ValueError("Identity mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise SiLabsSecurityError("Stored Saber pairing is missing or invalid.") from exc
        return record

    async def async_remove(self) -> None:
        await self._store.async_remove()
