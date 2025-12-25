from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import device_registry as dr

from .coordinator import LivoloCoordinator
from .const import DOMAIN, DEVICE_MODEL_TRANSLATIONS


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: LivoloCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = [LivoloOnlineSensor(coordinator, entry.entry_id, element_id) for element_id in coordinator.data.keys()]
    async_add_entities(entities)


class LivoloOnlineSensor(CoordinatorEntity[LivoloCoordinator], SensorEntity):
    _attr_icon = "mdi:lan-connect"

    def __init__(self, coordinator: LivoloCoordinator, entry_id: str, element_id: str) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._element_id = element_id
        self._attr_unique_id = f"{entry_id}_{element_id}_online"

    @property
    def _dev(self):
        return self.coordinator.data.get(self._element_id)

    def _translate_model(self, product_model: str):
        s = (product_model or "").strip()
        if not s:
            return ("", "")
        tr = DEVICE_MODEL_TRANSLATIONS.get(s)
        if tr:
            return tr
        for key, val in DEVICE_MODEL_TRANSLATIONS.items():
            if key and key in s:
                return val
        return ("", "")

    def _device_model_string(self) -> str:
        d = self._dev
        if not d:
            return ""
        en, ru = self._translate_model(d.product_model)
        if ru and en:
            return f"{ru} ({en})"
        if ru:
            return ru
        if en:
            return en
        return (d.product_model or "").strip()

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()

        d = self._dev
        if not d:
            return

        new_model = self._device_model_string()
        if not new_model:
            return

        dev_reg = dr.async_get(self.hass)

        device_entry = dev_reg.async_get_or_create(
            config_entry_id=self._entry_id,
            identifiers={(DOMAIN, d.element_id)},
            manufacturer="Livolo",
            name=d.name,
            model=new_model,
        )

        if device_entry.model != new_model or device_entry.name != d.name or device_entry.manufacturer != "Livolo":
            dev_reg.async_update_device(
                device_entry.id,
                manufacturer="Livolo",
                name=d.name,
                model=new_model,
            )

    @property
    def name(self) -> str:
        d = self._dev
        base = d.name if d else self._element_id
        return f"{base} Online"

    @property
    def native_value(self):
        d = self._dev
        return None if d is None else ("online" if d.is_online else "offline")

    @property
    def extra_state_attributes(self):
        d = self._dev
        if d is None:
            return {}

        en, ru = self._translate_model(d.product_model)
        return {
            "element_id": d.element_id,
            "product_key": d.product_key,
            "product_model": d.product_model,
            "room_name": d.room_name,
            "device_type_en": en or "Unknown",
            "device_type_ru": ru or "Неизвестно",
        }

    @property
    def device_info(self):
        d = self._dev
        if d is None:
            return None

        return DeviceInfo(
            identifiers={(DOMAIN, d.element_id)},
            name=d.name,
            manufacturer="Livolo",
            model=self._device_model_string() or None,
        )