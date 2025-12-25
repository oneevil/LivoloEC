from __future__ import annotations

import base64
import os
import uuid
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    DOMAIN,
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


class LivoloConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        if user_input is not None:
            data = dict(user_input)
            data[CONF_ROUTER_MAC] = _gen_router_mac()
            data[CONF_UMID_TOKEN] = _gen_umid_token()

            return self.async_create_entry(
                title=data[CONF_EMAIL],
                data=data,
            )

        schema = vol.Schema(
            {
                vol.Required(CONF_EMAIL): str,
                vol.Required(CONF_PASSWORD): str,
            }
        )

        return self.async_show_form(step_id="user", data_schema=schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return LivoloOptionsFlowHandler(config_entry)


class LivoloOptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry):
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        data = self.config_entry.data
        schema = vol.Schema(
            {
                vol.Required(CONF_EMAIL, default=data.get(CONF_EMAIL, "")): str,
                vol.Required(CONF_PASSWORD, default=data.get(CONF_PASSWORD, "")): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
