from __future__ import annotations

import aiohttp
import base64
import os
import uuid

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import LivoloClient
from .coordinator import LivoloCoordinator
from .const import (
    DOMAIN,
    PLATFORMS,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_ROUTER_MAC,
    CONF_UMID_TOKEN,
)


def _gen_router_mac() -> str:
    b = bytearray(os.urandom(6))
    b[0] = (b[0] | 0x02) & 0xFE
    return ":".join(f"{x:02x}" for x in b)


def _gen_umid_token() -> str:
    raw = uuid.uuid4().bytes + uuid.uuid4().bytes
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    session = aiohttp.ClientSession()

    router_mac = entry.data.get(CONF_ROUTER_MAC) or _gen_router_mac()
    umid_token = entry.data.get(CONF_UMID_TOKEN) or _gen_umid_token()

    client = LivoloClient(
        session,
        email=entry.data[CONF_EMAIL],
        password=entry.data[CONF_PASSWORD],
        country="DE",
        router_mac=router_mac,
        umid_token=umid_token,
    )

    coordinator = LivoloCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "session": session,
        "client": client,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if data:
        await data["session"].close()
    return unload_ok
