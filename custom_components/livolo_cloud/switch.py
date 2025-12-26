from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import LivoloDevice
from .const import DOMAIN
from .coordinator import LivoloCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client = data["client"]
    coordinator: LivoloCoordinator = data["coordinator"]

    devices: dict[str, LivoloDevice] = coordinator.data or {}

    entities: list[LivoloPowerSwitch] = [
        LivoloPowerSwitch(coordinator, client, dev, prop="PowerSwitch_1")
        for dev in devices.values()
    ]

    _LOGGER.debug("livolo_cloud: created %d switches", len(entities))
    async_add_entities(entities, update_before_add=False)


class LivoloPowerSwitch(CoordinatorEntity[LivoloCoordinator], SwitchEntity):
    def __init__(self, coordinator: LivoloCoordinator, client, device: LivoloDevice, prop: str) -> None:
        super().__init__(coordinator)
        self._client = client
        self._device = device
        self._prop = prop

        self._attr_has_entity_name = True
        self._attr_unique_id = f"{device.element_id}:{prop}"
        self._attr_name = device.name
        self._is_on = None

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._device.element_id)},
            "name": self._device.name,
            "manufacturer": "Livolo",
            "suggested_area": self._device.room_name or None,
        }

    @property
    def is_on(self):
        return self._is_on


    async def async_turn_on(self, **kwargs) -> None:
        await self._client.set_switch(element_id=self._device.element_id, on=True, prop=self._prop)
        self._is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        await self._client.set_switch(element_id=self._device.element_id, on=False, prop=self._prop)
        self._is_on = False
        self.async_write_ha_state()
