from __future__ import annotations

import asyncio
import json
import logging
import ssl
import threading
from dataclasses import dataclass
from typing import Any, Optional

import paho.mqtt.client as mqtt
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import SIGNAL_MQTT_STATE
from .mqtt_control import build_aliyun_app_mqtt_creds

_LOGGER = logging.getLogger(__name__)


@dataclass
class MqttStateUpdate:
    iot_id: str
    items: dict[str, Any]


class LivoloMqttListener:
    """Подключается к Aliyun MQTT и слушает app/down/thing/properties."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        client,
        entry_id: str,
        region: str,
        product_key: str,
        device_name: str,
        device_secret: str,
        use_tls: bool = True,
        port: int = 1883,
        verify_tls: bool = False,
        ca_certs: Optional[str] = None,
    ) -> None:
        self.hass = hass
        self._client_api = client
        self._entry_id = entry_id

        self._region = region
        self._pk = product_key
        self._dn = device_name
        self._ds = device_secret

        self._use_tls = use_tls
        self._port = port
        self._verify_tls = verify_tls
        self._ca_certs = ca_certs

        self._mqtt: mqtt.Client | None = None
        self._stop_evt = threading.Event()
        self._connected_evt = threading.Event()

        # state cache: (iotId, prop) -> bool
        self._states: dict[tuple[str, str], bool] = {}

    def get_state(self, iot_id: str, prop: str) -> bool | None:
        return self._states.get((iot_id, prop))

    async def async_start(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._start_sync)

    async def async_stop(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._stop_sync)

    def _start_sync(self) -> None:
        if self._mqtt is not None:
            return

        creds = build_aliyun_app_mqtt_creds(
            region=self._region,
            aep_product_key=self._pk,
            aep_device_name=self._dn,
            aep_device_secret=self._ds,
            use_tls=self._use_tls,
            mqtt_port=self._port,
            verify_tls=self._verify_tls,
            ca_certs=self._ca_certs,
        )

        topic_down = f"/sys/{self._pk}/{self._dn}/app/down/thing/properties"

        def on_connect(client: mqtt.Client, userdata, flags, rc, properties=None):
            if rc != 0:
                _LOGGER.error("Aliyun MQTT connect failed rc=%s", rc)
                return
            _LOGGER.info("Aliyun MQTT connected, subscribing %s", topic_down)
            self._connected_evt.set()
            client.subscribe(topic_down, qos=1)

        def on_disconnect(client: mqtt.Client, userdata, rc, properties=None):
            _LOGGER.warning("Aliyun MQTT disconnected rc=%s", rc)

        def on_message(client: mqtt.Client, userdata, msg: mqtt.MQTTMessage):
            try:
                payload = msg.payload.decode("utf-8", errors="replace").strip()
                if not payload:
                    return

                data = json.loads(payload)

                # В логах у тебя приходит список объектов: [ { "method":"thing.properties", ... } ]
                msgs = data if isinstance(data, list) else [data]

                for one in msgs:
                    if not isinstance(one, dict):
                        continue
                    if one.get("method") != "thing.properties":
                        continue

                    params = one.get("params") or {}
                    iot_id = params.get("iotId") or params.get("iotid") or params.get("iotID")
                    items = params.get("items") or {}
                    if not iot_id or not isinstance(items, dict):
                        continue

                    changed: dict[str, Any] = {}
                    for k, v in items.items():
                        # интересуют PowerSwitch_*
                        if not isinstance(k, str):
                            continue
                        if not k.startswith("PowerSwitch_"):
                            continue
                        # value может быть 0/1
                        try:
                            b = bool(int(v.get("value") if isinstance(v, dict) else v))
                        except Exception:
                            continue

                        self._states[(iot_id, k)] = b
                        changed[k] = b

                    if changed:
                        # дергаем HA thread-safe
                        self.hass.loop.call_soon_threadsafe(
                            async_dispatcher_send,
                            self.hass,
                            SIGNAL_MQTT_STATE,
                            self._entry_id,
                            MqttStateUpdate(iot_id=iot_id, items=changed),
                        )

            except Exception as e:
                _LOGGER.debug("Aliyun MQTT message parse error: %s", e)

        # paho-mqtt 2.x
        m = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION1,
            client_id=creds.client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
        )
        m.username_pw_set(creds.username, creds.password)

        if self._use_tls:
            if self._ca_certs:
                m.tls_set(
                    ca_certs=self._ca_certs,
                    cert_reqs=ssl.CERT_REQUIRED if self._verify_tls else ssl.CERT_NONE,
                    tls_version=ssl.PROTOCOL_TLS_CLIENT,
                )
            else:
                m.tls_set(
                    cert_reqs=ssl.CERT_REQUIRED if self._verify_tls else ssl.CERT_NONE,
                    tls_version=ssl.PROTOCOL_TLS_CLIENT,
                )
            m.tls_insecure_set(not self._verify_tls)

        m.on_connect = on_connect
        m.on_disconnect = on_disconnect
        m.on_message = on_message

        _LOGGER.info("Connecting Aliyun MQTT %s:%s TLS=%s", creds.host, creds.port, self._use_tls)
        m.connect(creds.host, creds.port, keepalive=60)
        m.loop_start()

        self._mqtt = m

    def _stop_sync(self) -> None:
        if self._mqtt is None:
            return
        try:
            self._mqtt.loop_stop()
            self._mqtt.disconnect()
        finally:
            self._mqtt = None
