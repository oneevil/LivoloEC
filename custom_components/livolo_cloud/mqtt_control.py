from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import string
import time
import random
from dataclasses import dataclass
from typing import Optional

import paho.mqtt.client as mqtt


@dataclass
class AliyunMqttCreds:
    host: str
    port: int
    client_id: str
    username: str
    password: str
    use_tls: bool
    verify_tls: bool
    ca_certs: Optional[str] = None


def _rand_client_id(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def build_aliyun_app_mqtt_creds(
    *,
    region: str,
    aep_product_key: str,
    aep_device_name: str,
    aep_device_secret: str,
    use_tls: bool = True,
    mqtt_port: int = 1883,
    verify_tls: bool = False,
    ca_certs: Optional[str] = None,
) -> AliyunMqttCreds:
    """
    Aliyun IoT Core (app) MQTT creds:

      username = "{deviceName}&{productKey}"
      clientId = "{raw}|securemode=2,signmethod=hmacsha1,timestamp={ts}|"
      password = HMACSHA1_HEX(deviceSecret,
                "clientId{raw}deviceName{dn}productKey{pk}timestamp{ts}")
    """
    ts = str(int(time.time() * 1000))
    raw = _rand_client_id()

    client_id = f"{raw}|securemode=2,signmethod=hmacsha1,timestamp={ts}|"
    username = f"{aep_device_name}&{aep_product_key}"

    sign_content = (
        f"clientId{raw}"
        f"deviceName{aep_device_name}"
        f"productKey{aep_product_key}"
        f"timestamp{ts}"
    )
    password = hmac.new(
        aep_device_secret.encode(),
        sign_content.encode(),
        hashlib.sha1,
    ).hexdigest()

    host = f"{aep_product_key}.iot-as-mqtt.{region}.aliyuncs.com"

    return AliyunMqttCreds(
        host=host,
        port=mqtt_port,
        client_id=client_id,
        username=username,
        password=password,
        use_tls=use_tls,
        verify_tls=verify_tls,
        ca_certs=ca_certs,
    )


def publish_switch_set(
    *,
    creds: AliyunMqttCreds,
    aep_product_key: str,
    aep_device_name: str,
    target_iot_id: str,
    prop_identifier: str,
    on: bool,
    timeout_s: int = 12,
) -> None:
    """
    Публикует команду через Aliyun app/up:

      topic: /sys/{pk}/{dn}/app/up/thing/service/property/set

      payload:
        {
          "id":"<millis>",
          "version":"1.0",
          "method":"thing.service.property.set",
          "params":{
            "iotId":"<target_iot_id>",
            "items":{"PowerSwitch_1":1/0}
          }
        }
    """
    topic = f"/sys/{aep_product_key}/{aep_device_name}/app/up/thing/service/property/set"

    payload = {
        "id": str(int(time.time() * 1000)),
        "version": "1.0",
        "method": "thing.service.property.set",
        "params": {
            "iotId": target_iot_id,
            "items": {prop_identifier: 1 if on else 0},
        },
    }
    payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    state = {"published": False, "err": None}

    def _on_connect(client, userdata, flags, rc, properties=None):
        if rc != 0:
            state["err"] = RuntimeError(f"MQTT connect failed rc={rc}")
            return
        info = client.publish(topic, payload_str, qos=1)
        info.wait_for_publish(timeout=timeout_s)
        state["published"] = True
        client.disconnect()

    # paho-mqtt 2.x требует указать CallbackAPIVersion при создании клиента. :contentReference[oaicite:2]{index=2}
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION1,
        client_id=creds.client_id,
        clean_session=True,
        protocol=mqtt.MQTTv311,
    )
    client.username_pw_set(creds.username, creds.password)
    client.on_connect = _on_connect

    if creds.use_tls:
        if creds.ca_certs:
            client.tls_set(
                ca_certs=creds.ca_certs,
                cert_reqs=ssl.CERT_REQUIRED if creds.verify_tls else ssl.CERT_NONE,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
        else:
            client.tls_set(
                cert_reqs=ssl.CERT_REQUIRED if creds.verify_tls else ssl.CERT_NONE,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )

        client.tls_insecure_set(not creds.verify_tls)

    client.connect(creds.host, creds.port, keepalive=60)
    client.loop_start()

    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if state["err"] is not None:
            client.loop_stop()
            raise state["err"]
        if state["published"]:
            client.loop_stop()
            return
        time.sleep(0.05)

    client.loop_stop()
    raise TimeoutError("MQTT publish timeout")
