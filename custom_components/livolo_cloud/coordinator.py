from __future__ import annotations

from datetime import timedelta
from typing import Dict

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import LivoloClient, LivoloApiError, LivoloAuthError, LivoloDevice
from .const import DOMAIN, UPDATE_INTERVAL_SECONDS


class LivoloCoordinator(DataUpdateCoordinator[Dict[str, LivoloDevice]]):
    def __init__(self, hass: HomeAssistant, client: LivoloClient) -> None:
        super().__init__(
            hass,
            logger=__import__("logging").getLogger(__name__),
            name=DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS),
        )
        self.client = client

    async def _async_update_data(self) -> Dict[str, LivoloDevice]:
        try:
            devices = await self.client.list_devices()
            return {d.element_id: d for d in devices}
        except (LivoloAuthError, LivoloApiError) as e:
            raise UpdateFailed(str(e)) from e
        except Exception as e:
            raise UpdateFailed(f"Unexpected error: {e}") from e
