"""Contracts for authenticated appliance capabilities and pairing storage."""

from __future__ import annotations

import asyncio
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from homeassistant.helpers.storage import Store as HomeAssistantStore

from custom_components.weber_connect import pairing_storage
from custom_components.weber_connect.capabilities import parse_capabilities
from custom_components.weber_connect.const import CONF_PAIRING_KEY_REF
from custom_components.weber_connect.diagnostics import async_get_config_entry_diagnostics
from custom_components.weber_connect.saber_frames import MAX_TLV_RECORDS
from custom_components.weber_connect.silabs_secure import (
    SiLabsSecurityError,
    SiLabsSigningKeys,
)


def tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag, len(value))) + value


def credentials(
    companion_id: bytes = bytes(range(16)),
    appliance_id: bytes = bytes(range(16, 32)),
    keys: SiLabsSigningKeys | None = None,
    peer_public_key: bytes | None = None,
    message_version: int = 11,
) -> pairing_storage.SiLabsCredentials:
    companion_keys = keys or SiLabsSigningKeys.generate()
    peer_keys = SiLabsSigningKeys.generate()
    return pairing_storage.SiLabsCredentials(
        companion_id,
        appliance_id,
        companion_keys,
        peer_public_key if peer_public_key is not None else peer_keys.public_key,
        message_version,
    )


class MemoryStore:
    """Small replacement for HA Store; no filesystem or device is involved."""

    records: ClassVar[dict[str, dict[str, Any]]] = {}
    constructions: ClassVar[list[tuple[Any, ...]]] = []

    def __class_getitem__(cls, _item: object) -> type[MemoryStore]:
        return cls

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.key = str(args[2])
        self.constructions.append((args, kwargs))

    async def async_save(self, value: dict[str, Any]) -> None:
        self.records[self.key] = value

    async def async_load(self) -> dict[str, Any] | None:
        return self.records.get(self.key)

    async def async_remove(self) -> None:
        self.records.pop(self.key, None)


@pytest.fixture(autouse=True)
def isolated_store(monkeypatch: pytest.MonkeyPatch) -> None:
    MemoryStore.records = {}
    MemoryStore.constructions = []
    monkeypatch.setattr(pairing_storage, "Store", MemoryStore)


def test_capabilities_parse_all_known_fields_and_ignore_unknown_tags() -> None:
    values = {
        1: ("probe_count", 2, 1),
        2: ("burner_count", 3, 1),
        6: ("region", 4, 1),
        8: ("control_interfaces", 0x0102030405060708, 8),
        9: ("sensor_interfaces", 0x1112131415161718, 8),
        12: ("device_class", 5, 1),
        21: ("capability_bits", 0x2122232425262728, 8),
        22: ("stop_cooking_duration_ms", 0x31323334, 4),
        23: ("fuel_type", 6, 1),
        24: ("max_wireless_probes", 7, 1),
    }
    payload = b"".join(
        tlv(tag, value.to_bytes(width, "little")) for tag, (_name, value, width) in values.items()
    )
    payload += tlv(99, b"unknown")

    assert parse_capabilities(payload) == {name: value for name, value, _ in values.values()}
    assert parse_capabilities(b"") == {}


@pytest.mark.parametrize("payload", [b"\x01", b"\x01\x02\x01", bytes((0, 255)) + b"x"])
def test_capabilities_reject_incomplete_or_truncated_records(payload: bytes) -> None:
    with pytest.raises(ValueError, match="incomplete or excessive"):
        parse_capabilities(payload)


def test_capabilities_reject_record_count_overflow() -> None:
    payload = tlv(99, b"") * (MAX_TLV_RECORDS + 1)
    with pytest.raises(ValueError, match="incomplete or excessive"):
        parse_capabilities(payload)


@pytest.mark.parametrize(
    "payload",
    [
        tlv(1, b"\x01") + tlv(1, b"\x02"),
        tlv(8, b"\x01" * 7),
        tlv(22, b"\x01" * 5),
    ],
)
def test_capabilities_reject_duplicate_and_wrong_width_scalars(payload: bytes) -> None:
    with pytest.raises(ValueError, match="invalid scalar field"):
        parse_capabilities(payload)


@pytest.mark.parametrize(
    ("companion", "appliance", "version", "peer"),
    [
        (b"short", bytes(range(16, 32)), 11, None),
        (bytes(range(16)), b"short", 11, None),
        (bytes(range(16)), bytes(range(16, 32)), 4, None),
        (bytes(range(16)), bytes(range(16, 32)), 12, None),
        (bytes(range(16)), bytes(range(16, 32)), 11, bytes(64)),
    ],
)
def test_credentials_validate_id_lengths_version_and_peer_key(
    companion: bytes, appliance: bytes, version: int, peer: bytes | None
) -> None:
    record = credentials(
        companion_id=companion,
        appliance_id=appliance,
        message_version=version,
        peer_public_key=peer,
    )
    with pytest.raises(SiLabsSecurityError):
        record.validate()


def test_credentials_validate_accepts_supported_message_version_bounds() -> None:
    for version in (5, 11):
        credentials(message_version=version).validate()


def test_storage_uses_private_atomic_ha_store_and_saves_only_hex_record() -> None:
    secret = credentials()
    reference = secret.companion_id.hex()
    hass = object()
    store = pairing_storage.PairingKeyStore(hass, reference)  # type: ignore[arg-type]

    args, kwargs = MemoryStore.constructions[0]
    assert args[0] is hass
    assert args[1:] == (1, f"weber_connect.pairing.{reference}")
    assert kwargs == {"private": True, "atomic_writes": True}

    asyncio.run(store.async_save(secret))
    saved = MemoryStore.records[f"weber_connect.pairing.{reference}"]
    assert saved == {
        "companion_id": reference,
        "appliance_id": secret.appliance_id.hex(),
        "signing_scalar": secret.keys.private_scalar.hex(),
        "peer_point": secret.peer_public_key.hex(),
        "message_version": secret.message_version,
    }


def test_save_rejects_reference_identity_mismatch() -> None:
    record = credentials()
    store = pairing_storage.PairingKeyStore(object(), "f" * 32)  # type: ignore[arg-type]

    with pytest.raises(SiLabsSecurityError, match="identity does not match"):
        asyncio.run(store.async_save(record))
    assert MemoryStore.records == {}


@pytest.mark.asyncio
async def test_save_load_reload_and_remove_preserve_raw_scalar_identity() -> None:
    record = credentials()
    reference = record.companion_id.hex()
    store = pairing_storage.PairingKeyStore(object(), reference)  # type: ignore[arg-type]
    await store.async_save(record)

    # A fresh wrapper and a scalar reconstruction must retain the exact keypair.
    reloaded = await pairing_storage.PairingKeyStore(object(), reference).async_load(
        record.appliance_id.hex()  # type: ignore[arg-type]
    )
    assert reloaded.keys.private_scalar == record.keys.private_scalar
    assert reloaded.keys.public_key == record.keys.public_key
    assert reloaded.peer_public_key == record.peer_public_key
    assert reloaded.appliance_id == record.appliance_id
    await store.async_remove()
    assert MemoryStore.records == {}


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"companion_id": "bad-hex"},
        {"companion_id": None},
        {
            "companion_id": bytes(range(16)).hex(),
            "appliance_id": bytes(range(16, 32)).hex(),
            "signing_scalar": bytes(32).hex(),
            "peer_point": credentials().peer_public_key.hex(),
            "message_version": 11,
        },
    ],
)
@pytest.mark.asyncio
async def test_load_rejects_missing_or_corrupted_record_without_leaking_data(
    data: dict[str, Any] | None,
) -> None:
    reference = bytes(range(16)).hex()
    store = pairing_storage.PairingKeyStore(object(), reference)  # type: ignore[arg-type]
    if data is not None:
        MemoryStore.records[f"weber_connect.pairing.{reference}"] = data

    with pytest.raises(SiLabsSecurityError, match="missing or invalid") as error:
        await store.async_load(bytes(range(16, 32)).hex())
    assert "bad-hex" not in str(error.value)


@pytest.mark.parametrize("requested_id", ["00" * 16, "not-hex"])
@pytest.mark.asyncio
async def test_load_enforces_appliance_identity(requested_id: str) -> None:
    record = credentials()
    store = pairing_storage.PairingKeyStore(object(), record.companion_id.hex())  # type: ignore[arg-type]
    await store.async_save(record)

    with pytest.raises(SiLabsSecurityError, match="missing or invalid"):
        await store.async_load(requested_id)


@pytest.mark.asyncio
async def test_load_enforces_companion_reference_identity() -> None:
    record = credentials()
    reference = record.companion_id.hex()
    store = pairing_storage.PairingKeyStore(object(), reference)  # type: ignore[arg-type]
    await store.async_save(record)
    MemoryStore.records[f"weber_connect.pairing.{reference}"]["companion_id"] = "f" * 32

    with pytest.raises(SiLabsSecurityError, match="missing or invalid"):
        await store.async_load(record.appliance_id.hex())


@pytest.mark.parametrize("reference", ["bad", "A" * 32, "g" * 32, "0" * 31, "0" * 33])
def test_storage_rejects_invalid_reference_before_store_construction(reference: str) -> None:
    with pytest.raises(SiLabsSecurityError, match="reference is invalid"):
        pairing_storage.PairingKeyStore(object(), reference)  # type: ignore[arg-type]
    assert MemoryStore.constructions == []


@pytest.mark.asyncio
async def test_secret_credentials_repr_and_diagnostics_do_not_expose_pairing_material() -> None:
    record = credentials()
    private_scalar = record.keys.private_scalar.hex()
    peer_point = record.peer_public_key.hex()
    rendered = repr(record)
    assert private_scalar not in rendered
    assert peer_point not in rendered

    # Pairing key references and pairing payload fields are never included in
    # the support-only diagnostics returned for an unloaded config entry.
    reference = record.companion_id.hex()
    entry = SimpleNamespace(
        data={
            CONF_PAIRING_KEY_REF: reference,
            "signing_scalar": private_scalar,
            "peer_point": peer_point,
        },
        options={},
        runtime_data=None,
    )
    diagnostics = await async_get_config_entry_diagnostics(
        object(),
        entry,  # type: ignore[arg-type]
    )
    serialized = str(diagnostics)
    for secret in (reference, private_scalar, peer_point):
        assert secret not in serialized


async def test_real_ha_private_storage_permissions_and_reload(
    hass: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Generated test keys verify private file permissions, never device credentials."""

    monkeypatch.setattr(pairing_storage, "Store", HomeAssistantStore)
    hass.config.config_dir = str(tmp_path)
    record = credentials()
    reference = record.companion_id.hex()
    store = pairing_storage.PairingKeyStore(hass, reference)
    await store.async_save(record)
    path = tmp_path / ".storage" / f"weber_connect.pairing.{reference}"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    reloaded = await pairing_storage.PairingKeyStore(hass, reference).async_load(
        record.appliance_id.hex()
    )
    assert reloaded.keys.private_scalar == record.keys.private_scalar
    await store.async_remove()
    assert not path.exists()


def saber_credentials(
    companion_id: bytes = bytes(range(16)),
    appliance_id: bytes = bytes(range(16, 32)),
    companion_public_key: bytes = bytes([0x33]) * 64,
    appliance_public_key: bytes = bytes([0x44]) * 64,
) -> pairing_storage.SaberSessionCredentials:
    return pairing_storage.SaberSessionCredentials(
        companion_id, appliance_id, companion_public_key, appliance_public_key
    )


@pytest.mark.asyncio
async def test_saber_session_round_trips_beside_silabs_records() -> None:
    record = saber_credentials()
    reference = record.companion_id.hex()
    store = pairing_storage.PairingKeyStore(object(), reference)  # type: ignore[arg-type]
    await store.async_save(record)

    assert MemoryStore.records[f"weber_connect.pairing.{reference}"]["family"] == "saber"
    reloaded = await store.async_load_saber(record.appliance_id.hex())
    assert reloaded == record
    # A Saber record is never mistaken for SiLabs keys.
    with pytest.raises(SiLabsSecurityError, match="missing or invalid"):
        await store.async_load(record.appliance_id.hex())
    assert record.companion_public_key.hex() not in repr(record)


@pytest.mark.parametrize(
    "record",
    [
        saber_credentials(companion_id=bytes(15)),
        saber_credentials(appliance_public_key=bytes(63)),
    ],
)
def test_saber_save_rejects_malformed_material(
    record: pairing_storage.SaberSessionCredentials,
) -> None:
    store = pairing_storage.PairingKeyStore(object(), "0" * 32)  # type: ignore[arg-type]
    with pytest.raises(SiLabsSecurityError, match="invalid"):
        asyncio.run(store.async_save(record))
    assert MemoryStore.records == {}


@pytest.mark.parametrize(
    ("stored", "appliance_id"),
    [
        (None, bytes(range(16, 32)).hex()),
        ("silabs", bytes(range(16, 32)).hex()),
        ("saber", "00" * 16),
        ("corrupt", bytes(range(16, 32)).hex()),
    ],
)
@pytest.mark.asyncio
async def test_saber_load_rejects_missing_foreign_or_mismatched_records(
    stored: str | None, appliance_id: str
) -> None:
    reference = bytes(range(16)).hex()
    store = pairing_storage.PairingKeyStore(object(), reference)  # type: ignore[arg-type]
    if stored == "silabs":
        await store.async_save(credentials())
    elif stored is not None:
        await store.async_save(saber_credentials())
        if stored == "corrupt":
            MemoryStore.records[f"weber_connect.pairing.{reference}"]["appliance_public_key"] = "zz"

    with pytest.raises(SiLabsSecurityError, match="Saber pairing is missing or invalid"):
        await store.async_load_saber(appliance_id)


@pytest.mark.asyncio
async def test_setup_loads_saber_keys_only_for_a_saber_entry_that_has_them() -> None:
    from custom_components.weber_connect import _async_load_saber_session
    from custom_components.weber_connect.const import CONF_APPLIANCE_ID, CONF_TRANSPORT_FAMILY

    record = saber_credentials()
    reference = record.companion_id.hex()
    await pairing_storage.PairingKeyStore(object(), reference).async_save(record)  # type: ignore[arg-type]

    def entry(**data: Any) -> Any:
        return SimpleNamespace(data={CONF_APPLIANCE_ID: record.appliance_id.hex(), **data})

    hass: Any = object()
    assert await _async_load_saber_session(hass, entry()) is None
    assert (
        await _async_load_saber_session(hass, entry(**{CONF_PAIRING_KEY_REF: reference})) == record
    )
    assert (
        await _async_load_saber_session(
            hass, entry(**{CONF_PAIRING_KEY_REF: reference, CONF_TRANSPORT_FAMILY: "saber"})
        )
        == record
    )
    assert (
        await _async_load_saber_session(
            hass,
            entry(**{CONF_PAIRING_KEY_REF: reference, CONF_TRANSPORT_FAMILY: "silabs_appliance"}),
        )
        is None
    )
    # A record that no longer loads leaves the entry on the cloud rather than dead.
    MemoryStore.records.clear()
    assert await _async_load_saber_session(hass, entry(**{CONF_PAIRING_KEY_REF: reference})) is None
